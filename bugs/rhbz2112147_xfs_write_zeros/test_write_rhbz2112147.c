/*
	Frank Sorenson <sorenson@redhat.com, 2022

	very heavily modified version of program & script provided by customer

	replicates a bug where simultaneous writes to a page may end up with
	zero-byte data


*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <syscall.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>

#define MAX_PROC		(50)
#define DEFAULT_PROC_COUNT	(5)

#define DEFAULT_TEST_COUNT	(100)
#define DEFAULT_THREAD_COUNT	(3)
#define MAX_THREADS		(100)
#define OFF_0			(768UL)

#define KiB			(1024ULL)
#define MiB			(KiB * KiB)
#define BUF_SIZE		(MiB)
#define FILE_SIZE		(BUF_SIZE * 100 + OFF_0)

#define TSTAMP_BUF_SIZE		(32)
#define DUMP_BYTE_COUNT		(128)

#define FILL_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"
static char fill_chars[] = FILL_CHARS;
#define FILL_LEN (sizeof(FILL_CHARS) - 1)


#ifndef PAGE_SIZE
#define PAGE_SIZE (4096)
#endif
#define VERIFY_BUF_SIZE (((OFF_0 + PAGE_SIZE - 1)/PAGE_SIZE) * PAGE_SIZE)

#define mb()	__asm__ __volatile__("mfence" ::: "memory")

#define UPDATE_DELAY_S 5
#define UPDATE_DELAY_US 0

struct shared_struct {
	bool exit_test;
	int filler[4];
	int test_counts[MAX_PROC];
	int replicated[MAX_PROC];
};
struct shared_struct *shared;

struct thread_args {
	char tstamp_buf[TSTAMP_BUF_SIZE]; // may only be used by a thread
	char *buf;

	pthread_t thread;
	int id;
	unsigned char c;
	off_t offset;
	int write_count;

	pid_t tid;
};

struct proc_args {
	int proc_num;
	struct thread_args thread_args[MAX_THREADS];
	char tstamp_buf[TSTAMP_BUF_SIZE]; // may only be used by the main test process
	char *name;
	char *log_name;

	unsigned int major;
	unsigned int minor;
	ino_t inode;

	pid_t pid;
	int fd; // fd of the testfile
	int log_fd;
	pthread_barrier_t bar;

	int test_count;
	bool replicated;

	pthread_mutex_t state_mutex;
} *proc_args;

struct globals {
	char tstamp_buf[TSTAMP_BUF_SIZE]; // may only be used by the main controlling process

	char *exe;
	char *base_dir_path;

	int stdout_fd;
	int stderr_fd;

	pid_t pid;
	int base_dir_fd;
	int testfile_dir_fd;
	int log_dir_fd;

	int proc_count;
	int running_proc_count;
	int test_count;
	int thread_count;

	int total_write_count; // total number of writes required to fill the file
	int extra_write_threads; // number of threads which will write an extra time
	size_t filesize;
	size_t buf_size;

	struct proc_args *proc;
	pid_t cpids[MAX_PROC];

	int replicated;
} globals;


pid_t gettid(void) {
	return syscall(SYS_gettid);
}

#define _PASTE(a,b) a##b
#define _PASTE3(a,b,c) a##b##c
#define PASTE(a,b) _PASTE(a,b)
#define PASTE3(a,b,c) _PASTE3(a,b,c)


#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define thread_output(_thread_output_fmt, ...) \
	output("%s  [%d / test proc %d / thread %d] " _thread_output_fmt, tstamp(thread_args->tstamp_buf), thread_args->tid, proc_args->proc_num, thread_args->id, ##__VA_ARGS__); \

#define proc_output(_proc_output_fmt, ...) \
	output("%s  [%d / test proc %d] " _proc_output_fmt, tstamp(proc_args->tstamp_buf), proc_args->pid, proc_args->proc_num, ##__VA_ARGS__);

#define global_output(_global_output_fmt, ...) \
	output("%s  [%d] " _global_output_fmt, tstamp(globals.tstamp_buf), globals.pid, ##__VA_ARGS__);

#define global_sig_output(_global_output_fmt, ...) /* expected to have our own buffer */ \
	output("%s  [%d] " _global_output_fmt, tstamp(tstamp_buf), globals.pid, ##__VA_ARGS__);

char *tstamp(char *buf) { // buf must be at least TSTAMP_BUF_SIZE in size
	struct timespec ts;
	struct tm tm_info;
	int len;

	clock_gettime(CLOCK_REALTIME, &ts);
	localtime_r(&ts.tv_sec, &tm_info);
	len = strftime(buf, TSTAMP_BUF_SIZE, "%F %T", &tm_info);
	len += snprintf(buf + len, TSTAMP_BUF_SIZE - len, ".%09ld", ts.tv_nsec);

	return buf;
}
void set_exit(bool value) {
	mb();
	shared->exit_test = value;
	mb();
}
bool get_exit(void) {
	mb();
	return shared->exit_test;
}
bool check_proc_replicated(int proc_num) {
	bool value;
	mb();
	value = shared->replicated[proc_num];
	mb();
	return value;
}
void set_proc_replicated(int proc_num, bool value) {
	mb();
	shared->replicated[proc_num] = value;
	mb();
}

void incr_test_count(int proc_num) {
	mb();
	shared->test_counts[proc_num]++;
	mb();
}

void handle_sig(int sig) {
	char tstamp_buf[TSTAMP_BUF_SIZE];

	if (sig != SIGPIPE) // otherwise we'd cause a SIGPIPE while handling SIGPIPE
		global_sig_output("caught signal %d; instructing test processes to exit\n", sig);
	set_exit(true);
}
void handle_child_exit(int sig, siginfo_t *info, void *ucontext) {
	char tstamp_buf[TSTAMP_BUF_SIZE];
	pid_t pid;
	int status, i;

	while ((pid = wait4(-1, &status, WNOHANG, NULL)) != -1) {
		bool found = false;
		if (pid == 0)
			return;

		for (i = 0 ; i < globals.proc_count ; i++) {
			if (globals.cpids[i] == pid) {
				if (check_proc_replicated(i)) {
					global_sig_output("child %d (pid %d) replicated the bug with device %d:%d inode %lu\n",
						i, pid, globals.proc[i].major, globals.proc[i].minor, globals.proc[i].inode);

					globals.replicated++;
					set_exit(true); // tell everyone else to exit
				} else {
					if (WIFSIGNALED(status)) {
						global_sig_output("child %d (pid %d) exiting with signal %d%s\n", i, pid,
							WTERMSIG(info->si_signo), WCOREDUMP(status) ? " and dumped core" : "");
					} else
						global_sig_output("child %d (pid %d) exited without replicating the bug\n", i, pid);
				}
				globals.cpids[i] = 0;
				globals.proc->pid = 0;

				i = globals.proc_count;
				found = true;
			}
		}
		if (found)
			continue;
		global_sig_output("unable to find exiting child pid %d\n", pid);
	}
}
void show_progress(int sig) {
	char tstamp_buf[TSTAMP_BUF_SIZE];
        int test_counts[MAX_PROC];
	int replicated_count = 0, running_count = 0, test_count = 0, i;

	mb();
	memcpy(test_counts, shared->test_counts, sizeof(int) * globals.proc_count);
	for (i = 0 ; i < globals.proc_count ; i++) {
		test_count += test_counts[i];
		if (globals.cpids[i])
			running_count++;
		if (check_proc_replicated(i))
			replicated_count++;
	}
	global_sig_output("%d test processes started, %d test processes running, %d tests started, bug replicated: %d\n",
		globals.proc_count, running_count, test_count, replicated_count);
}

#define min(a,b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a < _b ? _a : _b; \
})
#define max(a,b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a > _b ? _a : _b; \
})

void hexdump(const char *pre, const char *addr, off_t start_offset, size_t len) {
	size_t offset = 0;
	char buf[17];
	int i;

	while (offset < len) {
		int this_count = min(len - offset, 16);

		memcpy(buf, addr + offset, this_count);
		output("%s0x%08lx: ", pre, start_offset + offset);
		for (i = 0 ; i < 16 ; i++) {
			if (i < this_count)
				output("%02x ", buf[i]);
			else
				output("   ");
			if (i == 7)
				output("| ");
			if (i >= this_count)
				buf[i] = '\0';
			else if (! isprint(buf[i]))
				buf[i] = '.';
		}
		buf[i] = '\0';
		output(" |%s|\n", buf);
		offset += this_count;
	}
}

int check_replicated(void) {
	char *map, *ptr;
	int ret = 0, fd;
	struct stat st;

	if ((fd = openat(globals.testfile_dir_fd, proc_args->name, O_RDONLY|O_DIRECT)) < 0) {
//		output("%s  [%d / proc %d] unable to open file for verification: %m\n", tstamp(proc_args->tstamp_buf), proc_args->pid, proc_args->proc_num);
		proc_output("unable to open file for verification: %m\n");
		return 0;
	}

	fstat(fd, &st);

	//map = mmap(NULL, globals.filesize, PROT_READ, MAP_SHARED, proc_args->fd, 0);
	if ((map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) { // only map the actual size, in case the file is incomplete
		proc_output("mmap failed while verifying file contents: %m\n");
		ret = 0;
		goto out_close;
	}

	if ((ptr = memchr(map + OFF_0, 0, st.st_size - OFF_0))) {
		off_t offset = ptr - map;
		int dump_bytes = min(DUMP_BYTE_COUNT, st.st_size - offset + (DUMP_BYTE_COUNT>>1));

		proc_output("error: found zero bytes at offset 0x%08lx\n", offset);

		if (dump_bytes > 0) {
			hexdump("", ptr - (DUMP_BYTE_COUNT>>1), offset - (DUMP_BYTE_COUNT>>1), dump_bytes);
			ret = 1;
		}
	} else {
		proc_output("completed without replicating the bug\n");
		ret = 0;
	}
	munmap(map, st.st_size);
out_close:
	close(fd);

	return ret;
}

union multi_access {
	uint64_t u64[1];
	uint32_t u32[2];
	uint16_t u16[4];
	uint8_t u8[8];
};

#define DEFINE_MATCHLEN_FUNC(len) \
	__attribute__ ((gnu_inline)) inline \
	off_t PASTE(matchlen_u, len)(uint8_t *_a, uint8_t *_b) { \
		union multi_access *a = (union multi_access *)_a, *b = (union multi_access *)_b; \
		union multi_access d = { .u64[0] = 0 }; \
		\
		d.PASTE(u, len)[0] = a->PASTE(u, len)[0] ^ b->PASTE(u, len)[0]; \
		int clz = sizeof(PASTE3(uint, len, _t)); \
		\
		if (d.PASTE(u, len)[0]) \
			clz = __builtin_clzl(htobe64(d.PASTE(u, len)[0])) / 8; \
		\
		return clz; \
	}

#pragma GCC push_options
//#pragma GCC optimize("O3")

DEFINE_MATCHLEN_FUNC(8)
DEFINE_MATCHLEN_FUNC(16)
DEFINE_MATCHLEN_FUNC(32)
DEFINE_MATCHLEN_FUNC(64)
#define compare_mem_try_match(bits, a, b, len) do { \
	int ret; \
	if (len >= (bits/8)) { \
		if ((ret = PASTE(matchlen_u, bits)(a, b)) == (bits/8)) { \
			len -= (bits/8); \
			a += (bits/8); \
			b += (bits/8); \
			continue; \
		} \
		return (a - _a) + ret; \
	} \
} while (0)

off_t compare_mem(void *_a, void *_b, size_t len) {
	void *a = _a, *b = _b;
	while (len > 0) {
		compare_mem_try_match(64, a, b, len);
		compare_mem_try_match(32, a, b, len);
		compare_mem_try_match(16, a, b, len);
		compare_mem_try_match(8, a, b, len);
	}
	return (a - _a);
}
#pragma GCC pop_options


void *write_func(void *args_ptr) {
	struct thread_args *thread_args = (struct thread_args *)args_ptr;

	thread_args->tid = gettid();

	thread_output("alive, initial offset 0x%lx\n", thread_args->offset);
	if ((thread_args->buf = malloc(globals.buf_size)) == NULL) {
		thread_output("error allocating buffer: %m\n");
		goto out;
	}


	do {
		size_t this_write_count = min(globals.buf_size, globals.filesize - thread_args->offset);
		ssize_t wrsize;


		if (get_exit()) { // just skip to the end
			off_t offset = thread_args->offset;

			thread_output("exiting early after writing %lu bytes\n", offset);
			while (offset < globals.filesize) {
				pthread_barrier_wait(&proc_args->bar);

				offset += (globals.buf_size * globals.thread_count);
			}
			break;
		} else {

			memset(thread_args->buf, fill_chars[thread_args->c], this_write_count);

			pthread_barrier_wait(&proc_args->bar);
		}

		thread_output("offset 0x%lx, count 0x%lx, '%c' starting write\n",
			thread_args->offset, this_write_count, fill_chars[thread_args->c]);

		wrsize = pwrite(proc_args->fd, thread_args->buf, this_write_count, thread_args->offset);

		thread_output("offset 0x%lx, count 0x%lx, '%c' complete (0x%lx written)\n",
			thread_args->offset, this_write_count, fill_chars[thread_args->c], wrsize);

		if (wrsize != this_write_count) {
			thread_output("error writing to file: %m\n");
			goto out;
		}


char tmpbuf[BUF_SIZE];
pread(proc_args->fd, tmpbuf, this_write_count, thread_args->offset);
int matched_chars = compare_mem(thread_args->buf, tmpbuf, this_write_count);
if (matched_chars != this_write_count) {
	thread_output("re-read data does not match written data; mismatch at offset 0x%lx\n", thread_args->offset + matched_chars);
	thread_args->offset += this_write_count;
	set_exit(true);

	continue;	
}


		thread_args->write_count++;
		thread_args->offset += (globals.buf_size * globals.thread_count);
		thread_args->c = (thread_args->c + globals.thread_count) % FILL_LEN;
	} while (thread_args->offset < globals.filesize);


	if (thread_args->id >= globals.extra_write_threads) {
		thread_output("writes complete; waiting for other threads to complete\n");
		pthread_barrier_wait(&proc_args->bar);
	} else
		thread_output("writes complete\n");

out:
	if (thread_args->buf)
		free(thread_args->buf);
	return NULL;
}


int do_one_test(void) {
	int i, ret = EXIT_FAILURE;
	struct stat st;

	proc_output("starting test #%d\n", proc_args->test_count);

	if ((unlinkat(globals.testfile_dir_fd, proc_args->name, 0)) < 0 && errno != ENOENT) {
		proc_output("error removing file '%s/testfiles/%s': %m\n", globals.base_dir_path, proc_args->name);
		goto out;
	}

	if ((proc_args->fd = openat(globals.testfile_dir_fd, proc_args->name, O_CREAT|O_RDWR, 0644)) < 0) {
		proc_output("error opening file '%s/testfiles/%s': %m\n", globals.base_dir_path, proc_args->name);
		goto out;
	}

	fstat(proc_args->fd, &st);
	proc_args->major = major(st.st_dev);
	proc_args->minor = minor(st.st_dev);
	proc_args->inode = st.st_ino;

	proc_output("opened '%s/testfiles/%s' - device %d:%d inode %lu\n",
		globals.base_dir_path, proc_args->name, major(st.st_dev), minor(st.st_dev), st.st_ino);

	memset(proc_args->thread_args, 0, sizeof(struct thread_args) * globals.thread_count);

	if ((pthread_barrier_init(&proc_args->bar, NULL, globals.thread_count))) {
		proc_output("error calling pthread_barrier_init(): %m\n");
		goto out;
	}

	for (i = 0; i < globals.thread_count; i++) {
		proc_args->thread_args[i].id = i;
		proc_args->thread_args[i].c = i % FILL_LEN; // in case we have more threads than fill chars
		proc_args->thread_args[i].offset = OFF_0 + (globals.buf_size * i);
		if ((ret = pthread_create(&proc_args->thread_args[i].thread, NULL, write_func, &proc_args->thread_args[i])) != 0) {
			proc_output("pthread_create(%d) ret=%d\n", i, ret);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	for (i = 0; i < globals.thread_count; i++) {
		if ((ret = pthread_join(proc_args->thread_args[i].thread, NULL)) != 0) {
			proc_output("pthread_join(%d) ret=%d\n", i, ret);
			ret = EXIT_FAILURE;
			goto out;
		}
		proc_output("thread %d final offset=0x%lx\n", i, proc_args->thread_args[i].offset);

	}
// do we need to truncate like the file if the writes did not all complete?
#if 1
	size_t truncate_size = proc_args->thread_args[0].offset;
	for (i = 1 ; i < globals.thread_count ; i++) {
		if (proc_args->thread_args[i].offset > truncate_size)
			truncate_size = proc_args->thread_args[i].offset;
		else
			break;
	}
	if (truncate_size < globals.filesize) {

struct stat st;
fstat(proc_args->fd, &st);
if (st.st_size <= truncate_size) {
	proc_output("well... suppose I don't really need to truncate to its current size or larger (from %lu to %lu)\n", st.st_size, truncate_size);
} else {
		proc_output("truncating file from 0x%lx to size known to have completed: 0x%lx\n", st.st_size, truncate_size);
//output("filesize: %lu, truncate size: %lu\n", globals.filesize, truncate_size);
		ftruncate(proc_args->fd, truncate_size);
}
	}


#endif

	close(proc_args->fd);
	proc_args->fd = -1;


	proc_output("verifying file contents\n");
	if ((check_replicated()) == true) {
		ret = EXIT_SUCCESS;
		proc_args->replicated = true;
	}

out:
	if ((pthread_barrier_destroy(&proc_args->bar))) {
		proc_output("error calling pthread_barrier_destroy(): %m\n");
		// don't consider this fatal
	}

	if (proc_args->fd >= 0) {
		if (close(proc_args->fd))
			proc_output("error closing file: %m\n");
	}

	return ret == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

int do_one_proc(int proc_num) {
	int ret = EXIT_SUCCESS;

	proc_args = &globals.proc[proc_num];
	proc_args->pid = getpid();
	proc_args->state_mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

	proc_output("proc %d alive\n", proc_args->proc_num);

	if ((proc_args->log_fd = openat(globals.log_dir_fd, proc_args->log_name, O_CREAT|O_WRONLY|O_TRUNC, 0644)) < 0) {
		proc_output("error opening logfile '%s/logs/%s': %m\n", globals.base_dir_path, proc_args->log_name);
		ret = EXIT_FAILURE;
		goto out;
	}
	if ((dup3(proc_args->log_fd, fileno(stdout), 0)) < 0) {
		dprintf(globals.stderr_fd, "%s  [%d] error replacing stdout: %m\n", tstamp(proc_args->tstamp_buf), proc_args->pid);
//		proc_output("error replacing stdout: %m\n"); // will this actually go anywhere?
		ret = EXIT_FAILURE;
		goto out;
	}
	if ((dup3(proc_args->log_fd, fileno(stderr), 0)) < 0) {
		dprintf(globals.stderr_fd, "%s  [%d] error replacing stderr: %m\n", tstamp(proc_args->tstamp_buf), proc_args->pid);
//		proc_output("error replacing stderr: %m\n"); // will this actually go anywhere?
		ret = EXIT_FAILURE;
		goto out;
	}

	proc_output("proc %d alive\n", proc_args->proc_num); // repeat ourselves, now that we've got our own logfile

	for (proc_args->test_count = 1 ; proc_args->test_count <= globals.test_count ; proc_args->test_count++) {
		incr_test_count(proc_args->proc_num);

		ret = do_one_test();

		if (proc_args->replicated) {
			proc_output("test proc %d replicated the bug on test %d with device %d:%d inode %lu\n",
				proc_args->proc_num, proc_args->test_count,
				proc_args->major, proc_args->minor, proc_args->inode);
			set_proc_replicated(proc_args->proc_num, true);
			break;
		}

		if (ret == EXIT_FAILURE)
			break;
		if (get_exit()) {
			proc_output("exiting as requested\n");
			break;
		}
	}

out:
	free(proc_args->name);
	free(proc_args->log_name);
	if (proc_args->fd >= 0)
		close(proc_args->fd);

	dup3(globals.stdout_fd, fileno(stdout), 0); // restore stdout, close log
	dup3(globals.stderr_fd, fileno(stderr), 0); // restore stderr
	return ret;
}

int usage(int ret) {
	output("usage; %s <base_directory_path> [<process_count> [<thread_count>]]\n", globals.exe);
	output("\tdefault process count: %d\n", DEFAULT_PROC_COUNT);
	output("\tdefault thread count: %d\n", DEFAULT_THREAD_COUNT);
	return ret;
}
#define msg_usage0(ret, args...) do { \
	output(args); \
	return usage(ret); \
} while (0)

#define msg_usage(ret, args...) ({ \
	output(args); \
	usage(ret); \
})

void do_init(char *exe) {
	memset(&globals, 0, sizeof(globals));

	globals.exe = exe;
	globals.proc_count = DEFAULT_PROC_COUNT;
	globals.test_count = DEFAULT_TEST_COUNT;
	globals.thread_count = DEFAULT_THREAD_COUNT;
	globals.pid = getpid();
	globals.filesize = FILE_SIZE;
	globals.buf_size = BUF_SIZE;

	globals.base_dir_fd = -1;
	globals.testfile_dir_fd = -1;
	globals.log_dir_fd = -1;
}

void setup_handlers(void) {
	struct itimerval timer = {
		.it_value = { .tv_sec = UPDATE_DELAY_S, .tv_usec = UPDATE_DELAY_US },
		.it_interval = { .tv_sec = UPDATE_DELAY_S, .tv_usec = UPDATE_DELAY_US },
	};

	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sigfillset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &handle_sig;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);

	sigfillset(&sa.sa_mask);
	sa.sa_handler = &show_progress;
	sigaction(SIGALRM, &sa, NULL);
	setitimer(ITIMER_REAL, &timer, 0);

	sigfillset(&sa.sa_mask);
	sa.sa_handler = NULL;
	sa.sa_sigaction = &handle_child_exit;
	sigaction(SIGCHLD, &sa, NULL);

}

int do_testing() {
	sigset_t signal_mask;
	int ret, i;

	globals.total_write_count = (globals.filesize - OFF_0 + globals.buf_size - 1) / globals.buf_size; // total number of writes by all threads
	// all threads will write at least (globals.total_write_count / globals.thread_count)
	globals.extra_write_threads = globals.total_write_count % globals.thread_count;

	global_output("file size will be %ld (0x%lx) bytes, and buffer size will be %lu (0x%lx)\n", globals.filesize, globals.filesize, globals.buf_size, globals.buf_size);


	shared = mmap(NULL, sizeof(struct shared_struct), PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	shared->exit_test = false;

	globals.proc = mmap(NULL, sizeof(struct proc_args) * globals.proc_count, PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	globals.stdout_fd = dup(fileno(stdout));
	globals.stderr_fd = dup(fileno(stderr));


	if ((mkdir(globals.base_dir_path, 0777)) && errno != EEXIST) {
		global_output("error creating base dir '%s': %m\n", globals.base_dir_path);
		goto out;
	}
	if ((globals.base_dir_fd = open(globals.base_dir_path, O_RDONLY|O_DIRECTORY)) < 0) {
		global_output("error opening base  dir '%s': %m\n", globals.base_dir_path);
		goto out;
	}

	if ((mkdirat(globals.base_dir_fd, "testfiles", 0777)) && errno != EEXIST) {
		global_output("error creating testfile dir '%s/testfiles': %m\n", globals.base_dir_path);
		goto out;
	}
	if ((globals.testfile_dir_fd = openat(globals.base_dir_fd, "testfiles", O_RDONLY|O_DIRECTORY)) < 0) {
		global_output("error opening testfile dir '%s/testfiles': %m\n", globals.base_dir_path);
		goto out;
	}

	if ((mkdirat(globals.base_dir_fd, "logs", 0777)) && errno != EEXIST) {
		global_output("error creating log dir '%s/logs': %m\n", globals.base_dir_path);
		goto out;
	}
	if ((globals.log_dir_fd = openat(globals.base_dir_fd, "logs", O_RDONLY|O_DIRECTORY)) < 0) {
		global_output("error opening log dir '%s/logs': %m\n", globals.base_dir_path);
		goto out;
	}

	for (i = 0 ; i < globals.proc_count ; i++) {
		if ((asprintf(&globals.proc[i].name, "test%d", i)) < 0) {
			int j;
			global_output("error allocating memory for test file name 'test%d': %m\n", i);
			for (j = 0 ; j < i ; j++) {
				free(globals.proc[i].name);
				free(globals.proc[i].log_name);
			}
			goto out;
		}
		if ((asprintf(&globals.proc[i].log_name, "test%d.log", i)) < 0) {
			int j;
			global_output("error allocating memory for log file name 'test%d.log': %m\n", i);
			free(globals.proc[i].name);
			for (j = 0 ; j < i ; j++) {
				free(globals.proc[j].name);
				free(globals.proc[j].log_name);
			}
			goto out;
		}
	}

	set_exit(false);
	for (i = 0 ; i < globals.proc_count ; i++) {
		pid_t cpid;

		globals.proc[i].proc_num = i;

		if ((cpid = fork()) == 0) {
			return do_one_proc(i);
		} else if (cpid > 0) {
			globals.cpids[i] = cpid;
			globals.proc[i].pid = cpid;
			global_output("forked test proc %d as pid %d\n", i, globals.proc[i].pid);

			free(globals.proc[i].name); // at least free in the parent process
			free(globals.proc[i].log_name);
		} else {
			int j;

			global_output("error forking test proc %d (returned %d): %m\n", i, globals.proc[i].pid);
			for (j = 0 ; j < i ; j++) {
				kill(globals.cpids[j], SIGKILL); // just kill everything unceremoniously
			}
			return EXIT_FAILURE;
		}
	}


	setup_handlers();

	sigfillset(&signal_mask);
	sigdelset(&signal_mask, SIGCHLD);
	sigdelset(&signal_mask, SIGINT);
	sigdelset(&signal_mask, SIGPIPE);
	sigdelset(&signal_mask, SIGABRT);
	sigdelset(&signal_mask, SIGHUP);
	sigdelset(&signal_mask, SIGQUIT);
	sigdelset(&signal_mask, SIGALRM);

	while (42) {
		int running_count = 0;

		sigsuspend(&signal_mask);

		for (i = 0 ; i < globals.proc_count ; i++) {
			if (globals.cpids[i])
				running_count++;
		}
		if (! running_count)
			break;
	}

	if (globals.replicated) {
//		output("%s  [%d] exiting after replicating the bug %d time%s\n",
//			tstamp(globals.tstamp_buf), globals.pid, globals.replicated, globals.replicated == 1 ? "" : "s");
		global_output("exiting after replicating the bug %d time%s\n",
			globals.replicated, globals.replicated == 1 ? "" : "s");
		ret = EXIT_SUCCESS;
	} else {
//		output("%s  [%d] exiting without replicating the bug\n", tstamp(globals.tstamp_buf), globals.pid);
		global_output("exiting without replicating the bug\n");
		ret = EXIT_FAILURE;
	}

out:
	if (globals.testfile_dir_fd >= 0)
		close(globals.testfile_dir_fd);
	if (globals.log_dir_fd >= 0)
		close(globals.log_dir_fd);
	if (globals.base_dir_fd >= 0)
		close(globals.base_dir_fd);

	return ret;
}


int main(int argc, char *argv[]) {
	int ret = EXIT_FAILURE;

	do_init(argv[0]);

	if (argc < 2)
		return usage(EXIT_FAILURE);

	globals.base_dir_path = argv[1];

	if (argc > 2) {
		globals.proc_count = strtoul(argv[2], NULL, 10);
		if (globals.proc_count < 1 || globals.proc_count > MAX_PROC)
			return msg_usage(EXIT_FAILURE, "test process count must be between 1 and %d\n", MAX_PROC);
	}
	if (argc > 3) {
		globals.thread_count = strtoul(argv[3], NULL, 10);
		if (globals.thread_count < 1 || globals.thread_count > MAX_THREADS)
			return msg_usage(EXIT_FAILURE, "thread count should be between 1 and %d\n", MAX_THREADS);
	}

	ret = do_testing();

	return ret;;
}
