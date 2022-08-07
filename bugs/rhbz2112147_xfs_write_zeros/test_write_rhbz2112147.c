/*
	Frank Sorenson <sorenson@redhat.com, 2022

	very heavily modified version of program & script provided by customer

	replicates a bug where simultaneous writes to a page may end up with
	zero-byte data

	# gcc -Wall -lpthread -lm -g test_write_rhbz2112147.c -o test_write_rhbz2112147

	# ./test_write_rhbz2112147 <path_to_test_directory> [<options>]

	(execute without options to see the usage message)


	the reproducer will:
	 A. create <test_directory>/testfiles and <test_directory>/logs
	 B. spawn 40 (default; configurable) test processes
	  each test process will:
	   1. redirect stdout/stderr to a logfile at <test_directory>/logs/test##.log
	   2. delete the test file <test_directory>/testfiles/test##
	   3. create-open the file <test_directory>/testfiles/test## for testing
	   4. spawn 3 (default; configurable) threads
	    the threads will work together to write as much as 200 MiB (default; configurable)
		of non-zero data to the testfile, beginning at offset 0x300 (default; configurable)
	    a. all threads will wait at a barrier for synchronization
	    b. thread 0 will write 1 MiB (default; configurable) starting at offset 0x300
	    c. thread 1 will write 1 MiB starting at offset 0x10300 (the previous offset + 1 MiB)
	    d. thread 2 will write 1 MiB starting at offset 0x20300 (the previous offset + 1 MiB)

	    e. all threads will wait at a barrier for synchronization
	    f. thread 0 will write 1 MiB starting at offset 0x30300
	    g. thread 1 will write 1 MiB starting at offset 0x40300
	    h. thread 2 will write 1 MiB starting at offset 0x50300

	    i. all threads will wait at a barrier for synchronization
	    ...

	    ?. exit after writing its portions of the test file

	   5. the test process waits for completion of the child threads
	   6. close the test file
	   7. verify that the contents of the file are non-zero
	    a. if bug is reproduced:
	      (1) set a flag to denote successful reproduction
	    b. if bug is not reproduced:
	      (1) clear the state of the threads
	      (2) loop back to '2' above for as many as 100 (default; configurable) attempts

	   (after bug is reproduced or test count is exhausted)
	   8. close the logfile
	   9. exit

	 C. main process waits for test process exit
	  1. every 5 seconds (default; configurable) output message giving the status of the
		testing, including the number of running processes, total attempts to
		replicate the bug, and number of processes which have replicated it
	 D. examine the process's flag which denotes whether reproduction was successful
	   1. if bug is reproduced:
	     a. sets a global flag to indicate that all processes and threads should exit
	 E. wait for all test processes to exit
	 F. count the number of successful tests



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
#include <sys/syscall.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <math.h>
#include <limits.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/vfs.h>

#define DEFAULT_TEST_COUNT	(100)

#define DEFAULT_PROC_COUNT	(40)
#define MAX_PROC_COUNT		(100)

#define DEFAULT_THREAD_COUNT	(3)
#define MAX_THREAD_COUNT	(1000)


#define OFF_0			(768UL)

#define KiB			(1024ULL)
#define MiB			(KiB * KiB)
#define GiB			(KiB * KiB * KiB)


#define DEFAULT_OFF_0		(768UL)

#define DEFAULT_BUF_SIZE	(MiB)
#define MIN_BUF_SIZE		(128ULL)
#define MAX_BUF_SIZE		(MAX_FILE_SIZE)

#define DEFAULT_FILE_SIZE	(200ULL * MiB + DEFAULT_OFF_0) /* was based on size of buffer * a constant '500' + the offset */
#define MIN_FILE_SIZE		(4ULL * KiB)
#define MAX_FILE_SIZE		(10 * GiB)

#define DEFAULT_UPDATE_DELAY_S	(5)
#define DEFAULT_UPDATE_DELAY_US	(0)

#define TSTAMP_BUF_SIZE		(32)
#define DUMP_BYTE_COUNT		(128)

#define GETDENTS_BUF_SIZE	(64ULL * KiB)

#define FILL_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"
static char fill_chars[] = FILL_CHARS;
#define FILL_LEN (sizeof(FILL_CHARS) - 1)


#ifndef PAGE_SIZE
#define PAGE_SIZE (4096)
#endif

#if __x86_64__
#define mb()	__asm__ __volatile__("mfence" ::: "memory")
#elif __aarch64__
#define mb()	__asm__ __volatile__("dmb ish" ::: "memory") /* or should this be dsb ? */
#else
#error "Need to add memory barrier for this arch"
#endif


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


typedef enum { verify_mode_end, verify_mode_ongoing } verify_mode;

struct shared_struct {
	bool exit_test;
	int filler[4];
	int test_counts[MAX_PROC_COUNT];
	int replicated[MAX_PROC_COUNT];
};
struct shared_struct *shared;

struct thread_args {
	char tstamp_buf[TSTAMP_BUF_SIZE]; // may only be used by a thread
	char *buf;

	pthread_t thread;

	off_t offset;
	size_t size;

	pid_t tid;
	int id;
	int write_count;

	unsigned char c;
};

struct proc_args {
	int proc_num;
//	struct thread_args thread_args[MAX_THREAD_COUNT];
	char tstamp_buf[TSTAMP_BUF_SIZE]; // may only be used by the main test process
//	struct thread_args thread_args[MAX_THREAD_COUNT];
	struct thread_args *thread_args;
	char *name;
	char *log_name;

	unsigned int major;
	unsigned int minor;
	off_t replicated_offset;
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
	pid_t cpids[MAX_PROC_COUNT];
	char tstamp_buf[TSTAMP_BUF_SIZE]; // may only be used by the main controlling process

	struct utsname uts;

	struct timeval update_timer;

	char *exe;
	char *base_dir_path;
	char *canonical_base_dir_path;

	size_t filesize;
	size_t buf_size;
	off_t off0;

	struct proc_args *proc;

	int log_fd;
	FILE *log_FILE;
	int stdout_fd;
	int stderr_fd;

	pid_t pid;
	int base_dir_fd;
	int testfile_dir_fd;
	int log_dir_fd;

	verify_mode verify_mode;

	int proc_count;
	int running_proc_count;
	int test_count;
	int thread_count;

	int total_write_count; // total number of writes required to fill the file
	int extra_write_threads; // number of threads which will write an extra time

	int replicated;
} globals;


pid_t gettid(void) {
	return syscall(SYS_gettid);
}

#define _STR(s)	#s
#define STR(s) _STR(s)

#define _PASTE(a,b) a##b
#define _PASTE3(a,b,c) a##b##c
#define PASTE(a,b) _PASTE(a,b)
#define PASTE3(a,b,c) _PASTE3(a,b,c)

#define free_mem(addr) do { \
	if (addr) { \
		free(addr); \
		addr = NULL; \
	} \
} while (0)
#define close_fd(fd) do { \
	if (fd >= 0) { \
		if ((close(fd)) < 0) \
			output("error closing fd '%s': %m\n", \
				STR(fd)); \
		fd = -1; \
	} \
} while (0)

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define output_global_log_and_stdout(args...) do { \
	if (globals.log_fd >= 0) { \
		dprintf(globals.log_fd, args); \
		if (globals.log_FILE) \
			fflush(globals.log_FILE); \
	} \
	output(args); \
} while (0)

#define thread_output(_thread_output_fmt, ...) \
	output("%s  [%d / test proc %d / thread %d] " _thread_output_fmt, tstamp(thread_args->tstamp_buf), thread_args->tid, proc_args->proc_num, thread_args->id, ##__VA_ARGS__)

#define proc_output(_proc_output_fmt, ...) \
	output("%s  [%d / test proc %d] " _proc_output_fmt, tstamp(proc_args->tstamp_buf), proc_args->pid, proc_args->proc_num, ##__VA_ARGS__)

#define global_output(_global_output_fmt, ...) \
	output_global_log_and_stdout("%s  [%d] " _global_output_fmt, tstamp(globals.tstamp_buf), globals.pid, ##__VA_ARGS__)

#define global_sig_output(_global_output_fmt, ...) /* expected to have our own buffer */ \
	output("%s  [%d] " _global_output_fmt, tstamp(tstamp_buf), globals.pid, ##__VA_ARGS__)

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
					global_sig_output("test proc %d (pid %d) replicated the bug on test #%d with device %d:%d inode %lu at offset 0x%lx (%lu)\n",
						i, pid, globals.proc[i].test_count, globals.proc[i].major, globals.proc[i].minor, globals.proc[i].inode,
						globals.proc[i].replicated_offset, globals.proc[i].replicated_offset);

					globals.replicated++;
					set_exit(true); // tell everyone else to exit
				} else {
					if (WIFSIGNALED(status)) {
						global_sig_output("test proc %d (pid %d) exiting with signal %d%s\n", i, pid,
							WTERMSIG(info->si_signo), WCOREDUMP(status) ? " and dumped core" : "");
					} else
						global_sig_output("test proc %d (pid %d) exited without replicating the bug\n", i, pid);
				}
				globals.cpids[i] = 0;
				globals.proc[i].pid = 0;

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
	int test_counts[MAX_PROC_COUNT];
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


uint64_t l1024(uint64_t x) {
	uint64_t r = __builtin_clzll(x);

	if (x < 1024)
		return 0;
	if (r == (sizeof(x) * 8UL))
		return 0;
	return ((sizeof(x) * 8UL) - 1 - r) / 10;
}
#define units_base 1024
static char *unit_strings[] = { " bytes", "KiB", "MiB", "GiB", "GiB", "GiB", "EiB", "ZiB", "YiB" };
char *byte_units(uint64_t size) {
	char *ret;
	uint64_t divider;
	uint64_t d, rem;

	if (size < units_base) {
		asprintf(&ret, "%" PRIu64 " bytes", size);
	} else {
		int i = l1024(size);
		if (i > (sizeof(unit_strings)/sizeof(unit_strings[0])))
			i = sizeof(unit_strings)/sizeof(unit_strings[0]);

		divider = 1UL << (i * 10UL);

		d = size / divider;
		rem = size - (d * divider);
		rem = (rem * 100) / divider;

		asprintf(&ret, "%" PRIu64 ".%02" PRIu64 " %s", d, rem, unit_strings[i]);
	}
	return ret;
}

/* returns a size in bytes */
uint64_t parse_size(const char *size_str) {
	uint64_t uint_size = 0, ret;
	long double size;
	int shift = 0, have_uint = 0;
	char *p;

	uint_size = strtoull(size_str, NULL, 10);
	size = strtold(size_str, &p);

	if (fabsl((long double)uint_size - size) < 1e-9)
		have_uint = 1; /* integer, or close enough */

	while (*p != '\0' && (*p == '.' || *p == ' '))
		p++;
	if (*p != '\0') {
		if (strlen(p) <= 3) {
			if (strlen(p) == 2 && tolower(*(p+1)) != 'b')
				goto out_badsize;
			else if (strlen(p) == 3 &&
				(tolower(*(p+1)) != 'i' || tolower(*(p+2)) != 'b'))
				goto out_badsize;

			switch (tolower(*p)) {
				/* can't actually represent these */
				case 'y':
				case 'z':
					printf("size too large: %s\n", p);
					return 0;
					break;;
				case 'e': shift++;
				case 'p': shift++;
				case 't': shift++;
				case 'g': shift++;
				case 'm': shift++;
				case 'k':
					shift++;
					break;;
				default:
					goto out;
					break;;
			}
		} else
			goto out_badsize;
	}
	if (have_uint && shift)
		ret = uint_size * (1ULL << (shift * 10));
	else if (have_uint)
		ret = uint_size;
	else if (shift)
		ret = (uint64_t)(size * (long double)(1ULL << (shift * 10)));
	else
		ret = uint_size; /* might as well be an integer */
out:
	return ret;

out_badsize:
	printf("unrecognized size: '%s'\n", p);
	return 0;
}

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

off_t check_replicated(void) {
	char *map, *ptr;
	int ret = 0, fd = -1;
	struct stat st;

	if ((fd = openat(globals.testfile_dir_fd, proc_args->name, O_RDONLY|O_DIRECT)) < 0) {
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

	if ((ptr = memchr(map + globals.off0, 0, st.st_size - globals.off0))) {
		off_t offset = ptr - map;
		int dump_bytes = min(DUMP_BYTE_COUNT, st.st_size - offset + (DUMP_BYTE_COUNT>>1));

		proc_output("error: found zero bytes at offset 0x%08lx (%lu)\n", offset, offset);

		if (dump_bytes > 0)
			hexdump("", ptr - (DUMP_BYTE_COUNT>>1), offset - (DUMP_BYTE_COUNT>>1), dump_bytes);
		ret = offset;
	} else {
		proc_output("completed without replicating the bug\n");
		ret = 0;
	}
	munmap(map, st.st_size);
out_close:
	close_fd(fd);

	return ret;
}

void free_proc_paths(void) {
	int i;

	for (i = 0 ; i < globals.proc_count ; i++) {
		free_mem(globals.proc[i].name);
		free_mem(globals.proc[i].log_name);
	}
}
int alloc_proc_paths(void) {
	int ret = EXIT_FAILURE, i;

	for (i = 0 ; i < globals.proc_count ; i++) {
		if ((asprintf(&globals.proc[i].name, "test%d", i)) < 0) {
			ret = errno;
			globals.proc[i].name = NULL;
			free_proc_paths();
			goto out;
		}
		if ((asprintf(&globals.proc[i].log_name, "test%d.log", i)) < 0) {
			ret = errno;
			globals.proc[i].log_name = NULL;
			free_proc_paths();
			goto out;
		}
	}
	ret = EXIT_SUCCESS;
out:
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

	thread_output("alive, initial offset 0x%lx (%lu)\n", thread_args->offset, thread_args->offset);
	if ((thread_args->buf = malloc(globals.buf_size)) == NULL) {
		thread_output("error allocating buffer: %m\n");
		goto out;
	}

	do {
		size_t this_write_count = min(globals.buf_size, globals.filesize - thread_args->offset);
		ssize_t written;

		if (get_exit()) { // just skip to the end
			thread_output("exiting early after writing %d times\n", thread_args->write_count);
			goto out_wait;
#if 0
			off_t offset = thread_args->offset;

			while (offset < globals.filesize) {
				pthread_barrier_wait(&proc_args->bar);

				offset += (globals.buf_size * globals.thread_count);
			}
			break;
#endif
		}

		memset(thread_args->buf, fill_chars[thread_args->c], this_write_count);
		pthread_barrier_wait(&proc_args->bar);

		thread_output("write %d, offset 0x%lx (%lu), count 0x%lx (%lu), '%c' starting write\n",
			thread_args->write_count + 1, thread_args->offset, thread_args->offset,
			this_write_count, this_write_count, fill_chars[thread_args->c]);

		written = pwrite(proc_args->fd, thread_args->buf, this_write_count, thread_args->offset);

		thread_output("write %d, offset 0x%lx (%lu), count 0x%lx (%lu), '%c' complete (0x%lx (%lu) written)\n",
			thread_args->write_count + 1, thread_args->offset, thread_args->offset,
			this_write_count, this_write_count, fill_chars[thread_args->c], written, written);

		if (written != this_write_count) {
			thread_output("error writing to file: %m\n");
			goto out_error;
		}

		thread_args->size = thread_args->offset + this_write_count;
		thread_args->write_count++;

		if (globals.verify_mode == verify_mode_ongoing) {
			void *map;

			if ((map = mmap(NULL, this_write_count, PROT_READ, MAP_SHARED, proc_args->fd, thread_args->offset)) == MAP_FAILED) {
				thread_output("mmap failed while verifying file contents: %m\n");
				globals.verify_mode = verify_mode_end; // will this even take?
			} else {
				size_t matched_chars = compare_mem(thread_args->buf, map, this_write_count);
				if ((munmap(map, this_write_count)) < 0)
					thread_output("munmap returned an error after verifying file contents: %m\n");

				if (matched_chars != this_write_count) {
					thread_output("re-read data does not match written data; mismatch at offset 0x%lx (%lu)\n",
						thread_args->offset + matched_chars, thread_args->offset + matched_chars);
					proc_args->replicated = true;
					thread_args->offset += (globals.buf_size * globals.thread_count);
					set_exit(true);

					goto out_wait;
//					continue;	
				}
			}
		}

		thread_args->offset += (globals.buf_size * globals.thread_count);
		thread_args->c = (thread_args->c + globals.thread_count) % FILL_LEN;
	} while (thread_args->offset < globals.filesize);


	if (thread_args->id >= globals.extra_write_threads) {
		thread_output("writes complete; waiting for other threads to complete\n");
		pthread_barrier_wait(&proc_args->bar);
	} else
		thread_output("writes complete\n");

out:
	free_mem(thread_args->buf);
	return NULL;

out_error:
	thread_output("exiting on error; waiting on all threads\n");
	set_exit(true);

out_wait: /* need to spin on the barrier until all threads get the message */
	{
		off_t offset = thread_args->offset;

		while (offset < globals.filesize) {
			pthread_barrier_wait(&proc_args->bar);

			offset += (globals.buf_size * globals.thread_count);
		}
		if (thread_args->id >= globals.extra_write_threads) /* wait one extra time */
			pthread_barrier_wait(&proc_args->bar);
	}
	goto out;
}

// if some of the threads got an extra write() in, need to reduce the file size to the largest size known to have been written by all threads
//
// for the file size, determine which thread would have written the
//     (offset + length) to cause the file to become that size
// with n being the number of times this thread has written:
//     all the threads lower must also have at least n writes;
//     all the threads higher must have at least n-1 writes
void truncate_test_file(void) {
	struct stat st;
	int ending_thread, write_count, i;
	size_t truncate_size;

	fstat(proc_args->fd, &st);

	truncate_size = st.st_size;
	ending_thread = (((truncate_size - globals.off0) / globals.buf_size) - 1) % globals.thread_count; // the thread that would have caused the file to be this size
	write_count = proc_args->thread_args[ending_thread].write_count;

	proc_output("file size is 0x%lx (%lu), last written by thread %d, which wrote %d times to file size 0x%lx (%lu)\n",
		st.st_size, st.st_size, ending_thread, write_count,
		proc_args->thread_args[ending_thread].size, proc_args->thread_args[ending_thread].size);

	for (i = (ending_thread + globals.thread_count - 1) ; i > ending_thread ; i--) {
		int check_thread = i % globals.thread_count;

		proc_output("checking thread %d, which wrote %d times making file size 0x%lx (%lu)\n",
			check_thread, proc_args->thread_args[check_thread].write_count,
			proc_args->thread_args[check_thread].size, proc_args->thread_args[check_thread].size);

		if (check_thread < ending_thread && proc_args->thread_args[check_thread].write_count < write_count) {
			write_count = proc_args->thread_args[check_thread].write_count;
			truncate_size = proc_args->thread_args[check_thread].size;

			proc_output("reducing size to 0x%lx (%lu) due to write count for thread %d (%d)\n",
				truncate_size, truncate_size, check_thread, write_count);
		} else if (check_thread > ending_thread && proc_args->thread_args[check_thread].write_count < (write_count - 1)) {
			write_count = proc_args->thread_args[check_thread].write_count;
			truncate_size = proc_args->thread_args[check_thread].size;

			proc_output("reducing size to 0x%lx (%lu) due to write count for thread %d (%d)\n",
				truncate_size, truncate_size, check_thread, write_count);
		}
	}

	if (truncate_size < st.st_size) {
		proc_output("truncating file from 0x%lx (%lu) to size known to have completed: 0x%lx (%lu)\n",
			st.st_size, st.st_size, truncate_size, truncate_size);
		ftruncate(proc_args->fd, truncate_size);
	} else {
//		proc_output("well... suppose I don't really need to truncate to its current size or larger (from %lu to %lu)\n", st.st_size, truncate_size);
	}
}

int do_one_test(void) {
	int i, ret = EXIT_FAILURE;
	struct stat st;
	bool pthread_barrier_initialized = false;

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

	{ // fill the first off0 bytes so that the only 0-byte contents are actually the bug
		char *buf = NULL;
		int ret2;
		if ((buf = malloc(globals.off0)) == NULL) {
			proc_output("error allocating memory to write initial off0 bytes to test file: %m\n");
			goto out;
		}
		memset(buf, fill_chars[FILL_LEN - 1], globals.off0);
		if ((ret2 = pwrite(proc_args->fd, buf, globals.off0, 0)) != globals.off0)
			proc_output("error writing initial off0 bytes to test file: %m\n");
		free_mem(buf);
		if (ret2 != globals.off0)
			goto out;
	}

	memset(proc_args->thread_args, 0, sizeof(struct thread_args) * globals.thread_count);

	if ((pthread_barrier_init(&proc_args->bar, NULL, globals.thread_count))) {
		proc_output("error calling pthread_barrier_init(): %m\n");
		goto out;
	}
	pthread_barrier_initialized = true;

	for (i = 0; i < globals.thread_count; i++) {
		proc_args->thread_args[i].id = i;
		proc_args->thread_args[i].c = i % FILL_LEN; // in case we have more threads than fill chars
		proc_args->thread_args[i].offset = globals.off0 + (globals.buf_size * i);
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
		proc_output("thread %d wrote to file size 0x%lx (%lu)\n", i, proc_args->thread_args[i].size, proc_args->thread_args[i].size);

	}

	// if some of the threads got an extra write() in, need to reduce the file size to the largest size known to have been written by all threads
	truncate_test_file();

	close_fd(proc_args->fd);

	if (globals.verify_mode == verify_mode_end) {
		proc_output("test #%d verifying file contents\n", proc_args->test_count);
		if ((check_replicated()) == true) {
			ret = EXIT_SUCCESS;
			proc_args->replicated = true;
		}
	}

out:
	if ((pthread_barrier_initialized && pthread_barrier_destroy(&proc_args->bar)))
		proc_output("error calling pthread_barrier_destroy(): %m\n"); // don't consider this fatal

	close_fd(proc_args->fd);

	return ret == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

int do_one_proc(int proc_num) {
	int ret = EXIT_SUCCESS;

	proc_args = &globals.proc[proc_num];
	proc_args->pid = getpid();
	proc_args->state_mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

	proc_output("alive\n");

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

	proc_output("alive\n"); // repeat ourselves, now that we've got our own logfile

	proc_args->thread_args = malloc(sizeof(struct thread_args) * globals.thread_count);
	for (proc_args->test_count = 1 ; proc_args->test_count <= globals.test_count ; proc_args->test_count++) {
		incr_test_count(proc_args->proc_num);

		ret = do_one_test();

		if (proc_args->replicated) {
			proc_output("test proc %d replicated the bug on test #%d with device %d:%d inode %lu\n",
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
	close_fd(proc_args->fd);
	free_mem(proc_args->thread_args);

	dup3(globals.stdout_fd, fileno(stdout), 0); // restore stdout, close log
	dup3(globals.stderr_fd, fileno(stderr), 0); // restore stderr
	return ret;
}

int usage(int ret) {
	output("usage; %s [<options>] <base_directory_path>\n", globals.exe);

	output("\t-s | --file_size=<size>\t\t(default: %llu, min: %llu, max: %llu)\n", DEFAULT_FILE_SIZE, MIN_FILE_SIZE, MAX_FILE_SIZE);

	output("\t-b | --buffer_size=<size>\t\t(default: %llu, min: %llu, max: %llu)\n", DEFAULT_BUF_SIZE, MIN_BUF_SIZE, MAX_BUF_SIZE);
	output("\t-p | --processes=<process_count>\t(default: %d, max: %d)\n", DEFAULT_PROC_COUNT, MAX_PROC_COUNT);
	output("\t-t | --threads=<thread_count>\t\t(default: %d, max: %d)\n", DEFAULT_THREAD_COUNT, MAX_THREAD_COUNT);

	output("\t-c | --test_count=<test_count>\t\t(default: %d)\n", DEFAULT_TEST_COUNT);
	output("\t-o | --offset=<offset_bytes>\t\t(default: %lu)\n", DEFAULT_OFF_0);

	if (DEFAULT_UPDATE_DELAY_US) {
		uint32_t usec = DEFAULT_UPDATE_DELAY_US, rzero = 0, rdiv = 1;

		while ( usec >= 10 && usec % 10 == 0) {
			rzero++; rdiv *= 10; usec /= 10;
		}
		output("\t-u | --update_frequency=<seconds>\t(default: %d.%0*d seconds)\n", DEFAULT_UPDATE_DELAY_S, 6 - rzero, usec);
	} else
		output("\t-u | --update_frequency=<seconds>\t(default: %d seconds)\n", DEFAULT_UPDATE_DELAY_S);

	output("\t-v | --verify_end\t\t\tverify the file after all writes\n");
	output("\t-V | --verify_continuous\t\tverify the file after each write\n");

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

void setup_handlers(void) {
//        struct itimerval timer = { .it_value = globals.update_timer, .it_interval = globals.update_timer };
	struct itimerval timer;
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

	timer.it_value = globals.update_timer;
	timer.it_interval = globals.update_timer;
	sigfillset(&sa.sa_mask);
	sa.sa_handler = &show_progress;
	sigaction(SIGALRM, &sa, NULL);
	setitimer(ITIMER_REAL, &timer, 0);

	sigfillset(&sa.sa_mask);
	sa.sa_handler = NULL;
	sa.sa_sigaction = &handle_child_exit;
	sigaction(SIGCHLD, &sa, NULL);
}

struct linux_dirent64 {
	ino64_t		d_ino;    /* 64-bit inode number */
	off64_t		d_off;    /* 64-bit offset to next structure */
	unsigned short	d_reclen; /* Size of this dirent */
	unsigned char	d_type;   /* File type */
	char		d_name[]; /* Filename (null-terminated) */
};

size_t reclaim_disk(int _dfd) {
	struct linux_dirent64 *de;
	char *getdents_buf = NULL, *bpos;
	int nread;
	size_t reclaimable = 0, reclaimed = 0, reclaimed_reuse = 0, reclaim_failed = 0;
	int unreclaimable_objects = 0, dfd;
	struct stat st;

	global_output("attempting to reclaim disk space in the test directory '%s/testfiles'\n",
		globals.canonical_base_dir_path);

	if ((getdents_buf = malloc(GETDENTS_BUF_SIZE)) == NULL) {
		global_output("error allocating memory: %m\n");
		return 0;
	}

	if ((dfd = dup(_dfd)) < 0) {
		global_output("error duplicating the directory file descriptor: %m\n");
		goto out;
	}
	while (42) {
		if ((nread = syscall(SYS_getdents64, dfd, getdents_buf, GETDENTS_BUF_SIZE)) < 0)
			goto out;
		if (nread == 0)
			break;

		bpos = getdents_buf;
		while (bpos < getdents_buf + nread) {
			de = (struct linux_dirent64 *)bpos;

			bpos += de->d_reclen;

			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;

			if (de->d_type != DT_REG) { /* only care about files */
				unreclaimable_objects++;
				continue;
			}
			fstatat(dfd, de->d_name, &st, AT_NO_AUTOMOUNT|AT_SYMLINK_NOFOLLOW);

			if (strncmp(de->d_name, "test", 4) || strlen(de->d_name) <= 4) { /* doesn't start with test, or only contains test */
				reclaimable += st.st_size; /* could be reclaimed, but we're not doing so, since we don't know what it is */
			} else {
				char *p;
				uint32_t filenum = strtoul(de->d_name + 4, &p, 10);

				if ((filenum == ULONG_MAX && errno == ERANGE) || (*p != '\0')) {
global_output("here1 - p: '%s'\n", p);
					/* overflow or filename contains something after test### */
					reclaimable += st.st_size; /* could be reclaimed, but we're not doing so, since we don't know what it is */
					continue;
				}
global_output("deleting %s\n", de->d_name);
				if ((unlinkat(dfd, de->d_name, 0)) < 0) {
					global_output("error removing file '%s': %m\n", de->d_name);
					reclaim_failed += st.st_size;
					continue;
				}
				if (filenum >= globals.proc_count) /* not used on this run - pure reclaim */
					reclaimed += st.st_size;
				else
					reclaimed_reuse += st.st_size;
			}
		}
	}

	if (reclaimed_reuse) {
		char *reclaimed_reuse_str = byte_units(reclaimed_reuse);

		if (!reclaimed)
			global_output("reclaimed %lu bytes (%s), all of which can or will be reused in this test run\n",
				reclaimed_reuse, reclaimed_reuse_str);
		else {
			char *reclaimed_str = byte_units(reclaimed + reclaimed_reuse);
			global_output("reclaimed %lu bytes (%s), %lu (%s) of which can or will be reused in this test run\n",
				reclaimed + reclaimed_reuse, reclaimed_str, reclaimed_reuse, reclaimed_reuse_str);
			free_mem(reclaimed_str);
		}
		free_mem(reclaimed_reuse_str);
	} else if (reclaimed) {
		char *reclaimed_str = byte_units(reclaimed);
		global_output("reclaimed %lu bytes (%s)\n", reclaimed, reclaimed_str);

		free_mem(reclaimed_str);
	}
	if (reclaim_failed) {
		char *reclaim_failed_str = byte_units(reclaim_failed);
		global_output("tried to reclaim %lu bytes (%s), but failed with errors\n", reclaim_failed, reclaim_failed_str);
		free_mem(reclaim_failed_str);
	}
	if (reclaimable) {
		char *reclaimable_str = byte_units(reclaimable);
		global_output("test directory contains %lu bytes (%s) in unknown files, which could be reclaimed\n",
			reclaimable, reclaimable_str);
		free_mem(reclaimable_str);
	}
	if (unreclaimable_objects)
		global_output("test directory also contains at least %d of other entries (directories, etc.), which may be reclaimable\n",
			unreclaimable_objects);

out:
	free_mem(getdents_buf);
	close_fd(dfd);
	return reclaimed + reclaimed_reuse;
}

int do_testing() {
	sigset_t signal_mask;
	int ret = EXIT_FAILURE, i;
	off_t total_disk_required;
	char *total_disk_required_str = NULL;
	char *size1 = NULL, *size2 = NULL;
	struct statfs stfs;


	globals.stdout_fd = dup(fileno(stdout));
	globals.stderr_fd = dup(fileno(stderr));

	if ((mkdir(globals.canonical_base_dir_path, 0777)) && errno != EEXIST) {
		global_output("error creating base dir '%s': %m\n", globals.canonical_base_dir_path);
		goto out;
	}
	if ((globals.base_dir_fd = open(globals.canonical_base_dir_path, O_RDONLY|O_DIRECTORY)) < 0) {
		global_output("error opening base dir '%s': %m\n", globals.canonical_base_dir_path);
		goto out;
	}
	if ((globals.log_fd = openat(globals.base_dir_fd, "log.out", O_CREAT|O_TRUNC|O_WRONLY, 0644)) < 0) {
		global_output("error opening global logfile '%s/log.out': %m\n",
			globals.canonical_base_dir_path); /* I suppose we don't have to consider this fatal */
	} else {
		if ((globals.log_FILE = fdopen(globals.log_fd, "a")) == NULL)
			global_output("unable to reopen log fd: %m\n"); /* not super fatal either */
	}

	globals.total_write_count = (globals.filesize - globals.off0 + globals.buf_size - 1) / globals.buf_size; // total number of writes by all threads
	// all threads will write at least (globals.total_write_count / globals.thread_count)
	globals.extra_write_threads = globals.total_write_count % globals.thread_count;
	total_disk_required = globals.filesize * globals.proc_count;

	global_output("test running on '%s' arch '%s' kernel '%s'\n", globals.uts.nodename, globals.uts.machine, globals.uts.release);
	global_output("base directory for testing is '%s'\n", globals.canonical_base_dir_path);

	size1 = byte_units(globals.filesize);
	size2 = byte_units(globals.buf_size);
	global_output("size of each testfile is 0x%lx (%lu - %s) bytes, and buffer size will be 0x%lx (%lu - %s)\n",
		globals.filesize, globals.filesize, size1, globals.buf_size, globals.buf_size, size2);
	free_mem(size1);
	free_mem(size2);

	global_output("initial offset is 0x%lx (%ld)\n", globals.off0, globals.off0);
	global_output("creating %d test processes, each having %d threads\n", globals.proc_count, globals.thread_count);

	total_disk_required_str = byte_units(total_disk_required);
	global_output("tests will require approximately %lu bytes (%s) in the test directory (%s/testfiles)\n",
		total_disk_required, total_disk_required_str, globals.canonical_base_dir_path);

	shared = mmap(NULL, sizeof(struct shared_struct), PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	shared->exit_test = false;

	globals.proc = mmap(NULL, sizeof(struct proc_args) * globals.proc_count, PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);


	if ((mkdirat(globals.base_dir_fd, "testfiles", 0777)) && errno != EEXIST) {
		global_output("error creating testfile dir '%s/testfiles': %m\n", globals.canonical_base_dir_path);
		goto out;
	}
	if ((globals.testfile_dir_fd = openat(globals.base_dir_fd, "testfiles", O_RDONLY|O_DIRECTORY)) < 0) {
		global_output("error opening testfile dir '%s/testfiles': %m\n", globals.canonical_base_dir_path);
		goto out;
	}

	/* make sure we have enough disk space on this puppy */
	if ((fstatfs(globals.testfile_dir_fd, &stfs)) < 0) {
		global_output("error calling fstatfs() to verify free space: %m\n");
		goto out;
	}
	if (total_disk_required > stfs.f_blocks * stfs.f_bsize) { /* can't even reclaim and have enough */
		char *size_total = NULL;

		size_total = byte_units(stfs.f_blocks * stfs.f_bsize);

		global_output("error: disk space required (%lu - %s) exceeds total disk space (%lu - %s) at that location (%s)\n",
			total_disk_required, total_disk_required_str, stfs.f_blocks * stfs.f_bsize, size_total,
			globals.canonical_base_dir_path);

		free_mem(size_total);
		goto out;
	}

	/* remove existing testfiles */
	reclaim_disk(globals.testfile_dir_fd);

	if ((fstatfs(globals.testfile_dir_fd, &stfs)) < 0) {
		global_output("error calling fstatfs() to verify free space: %m\n");
		goto out;
	}
	if (total_disk_required > stfs.f_bfree * stfs.f_bsize) {
		char *size_avail = NULL, *size_short = NULL;

		size_avail = byte_units(stfs.f_bfree * stfs.f_bsize);
		size_short = byte_units(total_disk_required - (stfs.f_bfree * stfs.f_bsize));

		global_output("WARNING: disk space required (%lu - %s) exceeds available disk space (%lu - %s) at that location (%s) by at least %lu (%s)\n",
			total_disk_required, total_disk_required_str, stfs.f_bfree * stfs.f_bsize, size_avail, globals.canonical_base_dir_path,
			total_disk_required - (stfs.f_bfree * stfs.f_bsize), size_short);

		free_mem(size_avail);
		free_mem(size_short);

		goto out;
	}

	if ((mkdirat(globals.base_dir_fd, "logs", 0777)) && errno != EEXIST) {
		global_output("error creating log dir '%s/logs': %m\n", globals.canonical_base_dir_path);
		goto out;
	}
	if ((globals.log_dir_fd = openat(globals.base_dir_fd, "logs", O_RDONLY|O_DIRECTORY)) < 0) {
		global_output("error opening log dir '%s/logs': %m\n", globals.canonical_base_dir_path);
		goto out;
	}

	if ((ret = alloc_proc_paths()) != EXIT_SUCCESS) {
		global_output("error allocating memory for test process paths: %s\n", strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
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
		global_output("replicated the bug %d time%s\n",
			globals.replicated, globals.replicated == 1 ? "" : "s");
		for (i = 0 ; i < globals.proc_count ; i++) {
			if (check_proc_replicated(i)) {
				global_output("test proc %d on test #%d with %s/testfiles/%s - device %d:%d inode %lu\n",
					i, globals.proc[i].test_count, globals.canonical_base_dir_path, globals.proc[i].name,
					globals.proc[i].major, globals.proc[i].minor, globals.proc[i].inode);
				output("    replicated at offset 0x%lx (%lu)\n",
					globals.proc[i].replicated_offset, globals.proc[i].replicated_offset);
			}
		}
	} else
		global_output("did not replicate the bug\n");
out:
	close_fd(globals.testfile_dir_fd);
	close_fd(globals.log_dir_fd);
	close_fd(globals.base_dir_fd);
	close_fd(globals.log_fd);

	free_mem(total_disk_required_str);

	if (globals.proc) {
		free_proc_paths();
		munmap(globals.proc, sizeof(struct proc_args) * globals.proc_count);
	}

	return ret;
}

void do_init(char *exe) {
	memset(&globals, 0, sizeof(globals));

	globals.exe = exe;
	globals.proc_count = DEFAULT_PROC_COUNT;
	globals.thread_count = DEFAULT_THREAD_COUNT;
	globals.test_count = DEFAULT_TEST_COUNT;
	globals.pid = getpid();
	globals.filesize = DEFAULT_FILE_SIZE;
	globals.buf_size = DEFAULT_BUF_SIZE;
	globals.off0 = DEFAULT_OFF_0;

	globals.log_fd = -1;
	globals.base_dir_fd = -1;
	globals.testfile_dir_fd = -1;
	globals.log_dir_fd = -1;

	globals.verify_mode = verify_mode_end; // or verify_mode_ongoing
	globals.update_timer = (struct timeval){ .tv_sec = DEFAULT_UPDATE_DELAY_S, .tv_usec = DEFAULT_UPDATE_DELAY_US };

	uname(&globals.uts);
}

int parse_args(int argc, char *argv[]) {
	int opt = 0, long_index = 0;
	static struct option long_options[] = {
		{ "file_size",	required_argument, 0, 's' },
		{ "buffer_size",	required_argument, 0, 'b' },
		{ "processes",	required_argument, 0, 'p' },
		{ "threads",	required_argument, 0, 't' },
		{ "offset",	required_argument, 0, 'o' },
		{ "test_count",	required_argument, 0, 'c' },
		{ "update_frequency", required_argument, 0, 'u' },

		{ "verify_end",	no_argument, 0, 'v' },
		{ "verify_continuous",	no_argument, 0, 'V' },
		{ NULL, 0, 0, 0 },
	};
	int ret = EXIT_SUCCESS;

	do_init(argv[0]);

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "s:b:p:t:o:c:u:vV", long_options, &long_index)) != -1) {
		switch (opt) {
			case 's':
				globals.filesize = parse_size(optarg);

				if (globals.filesize == 0)
					return msg_usage(EXIT_FAILURE, "unable to parse filesize '%s'\n", optarg);
				if (globals.filesize < MIN_FILE_SIZE || globals.filesize > MAX_FILE_SIZE)
					return msg_usage(EXIT_FAILURE, "invalid file size '%s'; size must be between %llu and %llu\n", optarg, MIN_FILE_SIZE, MAX_FILE_SIZE);
				break;
			case 'b':
				globals.buf_size = parse_size(optarg);
				if (globals.buf_size == 0)
					return msg_usage(EXIT_FAILURE, "unable to parse buffer size '%s'\n", optarg);
				if (globals.buf_size < MIN_BUF_SIZE || globals.buf_size > MAX_BUF_SIZE)
					return msg_usage(EXIT_FAILURE, "invalid bufrer size '%s'; size must be between %llu and %llu\n", optarg, MIN_BUF_SIZE, MAX_BUF_SIZE);
				break;
			case 'p':
				globals.proc_count = strtoul(optarg, NULL, 10);
				if (globals.proc_count < 1 || globals.proc_count > MAX_PROC_COUNT)
					return msg_usage(EXIT_FAILURE, "invalid number of proceses '%s'; test process count must be between 1 and %d\n", optarg, MAX_PROC_COUNT);
				break;
			case 't':
				globals.thread_count = strtoul(optarg, NULL, 10);
				if (globals.thread_count < 1 || globals.thread_count > MAX_THREAD_COUNT)
					return msg_usage(EXIT_FAILURE, "invalid thread count '%s'; thread count must be be between 1 and %d\n", optarg, MAX_THREAD_COUNT);
				break;
			case 'o':
				globals.off0 = strtoul(optarg, NULL, 10);
				break;
			case 'c':
				globals.test_count = strtoul(optarg, NULL, 10);
				break;
			case 'u': {
				char *endp;
				globals.update_timer.tv_sec = strtoul(optarg, &endp, 10);
				if (globals.update_timer.tv_sec == ULONG_MAX) {
					if (errno == ERANGE)
						return msg_usage(EXIT_FAILURE, "could not convert '%s' to seconds\n", optarg);
					return msg_usage(EXIT_FAILURE, "unknown parsing error with '%s': %m\n", optarg);
				}
				if (*endp == '.') {
					uint64_t mult = 1000000;

					endp++;
					while (isdigit(*endp)) {
						globals.update_timer.tv_usec += mult * (*endp - '0');
						mult /= 10;
						endp++;

						if (!mult)
							break;
					}
				}
				break;
			}
			case 'v': globals.verify_mode = verify_mode_end; break;
			case 'V': globals.verify_mode = verify_mode_ongoing ; break;
			default: {
				return msg_usage(EXIT_FAILURE, "unrecognized option '%c'\n", opt);
				break;
			}
		}
	}

	if (optind >= argc)
		return msg_usage(EXIT_FAILURE, "No path specified\n");
	globals.base_dir_path = argv[optind++];
	if ((globals.canonical_base_dir_path = canonicalize_file_name(globals.base_dir_path)) == NULL)
		return msg_usage(EXIT_FAILURE, "Unable to canonicalize '%s': %m\n", globals.base_dir_path);

	return ret;
}

int main(int argc, char *argv[]) {
	int ret = EXIT_FAILURE;

	if ((ret = parse_args(argc, argv)) != EXIT_SUCCESS)
		goto out;

	ret = do_testing();

out:
	free_mem(globals.canonical_base_dir_path);

	return ret;
}
