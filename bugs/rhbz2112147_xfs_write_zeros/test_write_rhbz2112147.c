/*
	Frank Sorenson <sorenson@redhat.com, 2022

	very heavily modified version of program & script provided by customer

	replicates a bug where simultaneous writes to a page may end up with
	zero-byte data


	# gcc -Wall -lpthread -lm -g test_write_rhbz2112147.c -o test_write_rhbz2112147

	# ./test_write_rhbz2112147 [<options>] <path_to_test_directory>



	(execute without options to see the usage message)


	the reproducer will:
	 A. create <test_directory>/testfiles and <test_directory>/logs
	 B. create a cgroup (v1 or v2)
	 C. spawn ## (default is number of online cpus; configurable) test processes
	  each test process will:
	   1. redirect stdout/stderr to a logfile at <test_directory>/logs/test##.log
	   2. delete the test file <test_directory>/testfiles/test##
	   3. create-open the file <test_directory>/testfiles/test## for testing
	   4. writes non-zero data to the first 0x300 (default; configurable) bytes
	   5. enter the test cgroup
	   6. spawn 3 (default; configurable) threads

	    ONCE: all threads will wait while the main process measures current memory usage
		and continues once it sees that the main process has set the 'hard limit'

	    the threads will work together to write as much as 300 MiB (default; configurable)
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

	   7. the test process waits for completion of the child threads
	   8. close the test file
	   9. verify that the contents of the file are non-zero
	    a. if bug is reproduced:
	      (1) set a flag to denote successful reproduction
	    b. if bug is not reproduced:
	      (1) clear the state of the threads
	      (2) loop back to '2' above for as many as 100 (default; configurable) attempts

	   (after bug is reproduced, test count is exhausted, or instructed by main process)
	   10. close the logfile
	   11. exit

	 D. ONCE: wait for all threads to start and set cgroup limits:
	  1. read from the cgroup's "current memory usage" file -> 'mem_min'
	  2. set the cgroup's soft limit (v1: memory.soft_limit_in_bytes, v2: memory.high)
		to the value:  mem_min + (mem_min / 2)
	  3. set the cgroup's hard limit (v1: memory.limit_in_bytes, v2: memory.max)
		to the value:  mem_min * 2

	 E. main process waits for test process exit
	  1. every 1 second (default; configurable) output message giving the status of the
		testing, including the number of running processes, total attempts to
		replicate the bug, and number of processes which have replicated it
	 F. restarts test processes if they they exited on an error
	 G. examine the process's flag which denotes whether reproduction was successful
	   1. if bug is reproduced:
	     a. sets a global flag to indicate that all processes and threads should exit
	 H. wait for all test processes to exit
	 I. count the number of successful tests


	Program can be interrupted, and test processes should exit.
	    1 - processes will exit after completing this current test and verification
	    2 - processes will exit now, and verify the bytes written
	    3 - processes will exit now, without verifying bytes written
	    4 - processes will be unceremoniously killed (signal 9)
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
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/resource.h>
#include <linux/magic.h>

#define PAGE_SIZE_4K		(4096UL)

#define DEFAULT_TEST_COUNT	(100)

#define MAX_PROC_COUNT		(1000)

#define DEFAULT_THREAD_COUNT	(3)
#define MAX_THREAD_COUNT	(1000)

#define KiB			(1024ULL)
#define MiB			(KiB * KiB)
#define GiB			(KiB * KiB * KiB)

#define USEC_TO_NSEC(v)		(v * 1000UL)
#define MSEC_TO_NSEC(v)		(v * 1000000UL)

#define DEFAULT_OFF_0		(768UL)

#define DEFAULT_BUF_SIZE	(MiB)
#define MIN_BUF_SIZE		(128ULL) // arbitrary, but we should make _some_ limit
#define MAX_BUF_SIZE		(MAX_FILE_SIZE)

#define DEFAULT_FILE_SIZE	(300ULL * MiB + DEFAULT_OFF_0)
#define MIN_FILE_SIZE		(4ULL * KiB)
#define MAX_FILE_SIZE		(10 * GiB) // arbitrary, but there ought to be a limit

#define DEFAULT_UPDATE_DELAY_S	(1)
#define DEFAULT_UPDATE_DELAY_US	(0)

#define TSTAMP_BUF_SIZE		(32) // string at least long enough to contain timestamp:  YYYY-MM-DD HH:MM:SS.sssssssss'
#define DUMP_BYTE_COUNT		(128)

#define GETDENTS_BUF_SIZE	(64ULL * KiB)


#define INTERRUPT_COUNT_REALLY_EXIT	(4) /* after this many interrupts, start murdering processes */

#define FILL_CHARS " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

static char fill_chars[] = FILL_CHARS;
#define FILL_LEN (sizeof(FILL_CHARS) - 1)

#define CGROUP_PATH "/sys/fs/cgroup"
#define CGROUP_NAME "rhbz2112147"

#define CGROUP_V1_GROUP_PATH		CGROUP_PATH "/memory/" CGROUP_NAME
#define CGROUP_V1_CURRENT_USAGE_FILE	"memory.usage_in_bytes"
#define CGROUP_V1_HIGH_FILE		"memory.soft_limit_in_bytes"
#define CGROUP_V1_MAX_FILE		"memory.limit_in_bytes"

#define CGROUP_V2_GROUP_PATH		CGROUP_PATH "/" CGROUP_NAME
#define CGROUP_V2_CURRENT_USAGE_FILE	"memory.current"
#define CGROUP_V2_HIGH_FILE		"memory.high"
#define CGROUP_V2_MAX_FILE		"memory.max"


#define PROC_RESTART_HOLDOFF (struct timespec){ .tv_sec = 3, .tv_nsec = MSEC_TO_NSEC(0) }

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
#define clamp(val, min, max) ({                 \
	typeof(val) __val = (val);              \
	typeof(min) __min = (min);              \
	typeof(max) __max = (max);              \
	(void) (&__val == &__min);              \
	(void) (&__val == &__max);              \
	__val = __val < __min ? __min: __val;   \
	__val > __max ? __max: __val; })


#define PTHREAD_TBARRIER_CANCELED	(-2)
// function looks like:  bool cancel_func(void);
typedef bool (*tbarrier_csncel_func_t)(void);

/* a cancelable barrier */
struct pthread_tbarrier {
	pthread_cond_t cond;
	pthread_mutex_t lock;
	struct timespec freq; // how long to wait between calls to ->cancel function to check whether to break out

	uint32_t target_count;
	uint32_t threads_left; // alternatively, current_wait_count
	uint32_t cycle;
	bool initialized;
	tbarrier_csncel_func_t cancel; // function to call to check whether to break out of the barrier wait
};
typedef struct pthread_tbarrier pthread_tbarrier_t;

typedef enum { no_exit = 0, exit_after_test, exit_now_verify, exit_now, exit_kill } exit_urgency;

typedef enum { not_exiting = 0, exit_error, exit_interrupt, exit_on_flag, exit_test_count, exit_replicated } exit_reason;
typedef enum { process_type_main, process_type_proc, process_type_thread } process_type;
/*
static char *exit_reason_strings[] = {
	[not_exiting] = "not exiting",
	[exit_error] = "Exiting due to error",
	[exit_interrupt] = "Exiting due to interrupt",
	[exit_on_flag] = "Exiting due to global exit flag",
	[exit_test_count] = "Exiting after performing test count",
	[exit_replicated] = "Exiting after replicating the bug",
};
*/

struct bug_result {
	off_t offset; /* offset of zero data */
	size_t length; /* length of zeroed data */
};
struct bug_results {
	int count; /* number of result entries */
	struct bug_result result[0];
};

struct shared_struct {
	exit_urgency exit_test;
	uint64_t test_count;
	int running_count;
	int replicated_count;
	int writing_count;
	int verifying_count;
	int completed_count;

	int threads_running;

	uint64_t mem_min;
	uint64_t mem_high;
	uint64_t mem_max;
};

struct thread_args {
	char *buf;

	pthread_t thread;

	off_t offset; /* location of write */
	size_t size; /* size which this process's latest write made the file */

	pid_t tid;
	int id;
	int write_count;
	unsigned char c;
	exit_reason exit_reason;
};

struct proc_args {
	int proc_num;
	struct thread_args *thread_args;
	char **thread_bufs;
	char *name;
	char *log_name;

	unsigned int major;
	unsigned int minor;
	ino_t inode;

	pid_t pid;
	int fd; // fd of the testfile
	int log_fd;
	FILE *log_FILE;

	pthread_tbarrier_t tbar1;
	pthread_tbarrier_t tbar2;

	pthread_key_t thread_id_key;
	pthread_key_t thread_key;

	uint32_t write_round;
	uint32_t last_verify_round;
	size_t last_verified_size;
	size_t current_size;

	int memfd;
	struct bug_results *results;

	int test_count;
	int replicated;

	bool exit_test;
	exit_reason exit_reason;

	int write_errors;
	int children_exited;

	int interrupted;
} *proc_args;

struct globals {
	pid_t *cpids;

	struct utsname uts;

	struct timespec start_time;
	struct timespec end_time;
	struct timeval update_timer;

	char *exe;
	char *base_dir_path;
	char *canonical_base_dir_path;

	size_t filesize;
	size_t buf_size;
	off_t off0;

	struct proc_args *proc;
	struct shared_struct *shared;
	long page_size;
	int online_cpus;

	int cgroup_vers;
	char *cgroup_path;
	int cgroup_fd;
	int main_prio;
	int proc_prio;

	int log_fd;
	FILE *log_FILE;
	int stdout_fd;
	int stderr_fd;

	pid_t pid;
	int base_dir_fd;
	int testfile_dir_fd;
	int log_dir_fd;

	uint32_t verify_frequency;

	pthread_key_t process_args_key;

	pthread_key_t thread_id_key;
	pthread_key_t proc_id_key;
	pthread_key_t process_type_key;

	int proc_count;
	int test_count;
	int thread_count;

	int interrupt_count; /* how many times we've received a non-SIGCHLD interrupt (i.e. told to stop) */
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

#define free_mem(addr) ({ \
	if (addr) \
		free(addr); \
	addr = NULL; \
	addr; })
#define do_munmap(var, size) ({ \
	if (var && var != MAP_FAILED) \
		if ((munmap(var, size)) < 0) { \
			tstamp_output("[%d] %s() @ %s:%d - error unmapping '%s' (%lu bytes): %m\n", \
				gettid(), __func__, __FILE__, __LINE__, STR(size), size); \
		} \
	var = NULL; \
	var; })

#define close_fd(fd) ({ \
	int rc = 0; \
	if (fd >= 0) { \
		if ((close(fd)) < 0) { \
			tstamp_output("%d] %s() @ %s:%d - error closing fd '%s': %m\n", \
				gettid(), __func__, __FILE__, __LINE__, STR(fd)); \
			rc = 1; \
		} \
		fd = -1; \
	} \
	rc; })

#define close_FILE(fh, fd) do { \
	if (fh) { \
		if (fclose(fh) == EOF) \
			tstamp_output("[%d] %s() @ %s:%d - error closing file handle '%s' / fd '%s': %m\n", \
				gettid(), __func__, __FILE__, __LINE__, STR(fh), STR(fd)); \
		fh = NULL; \
		fd = -1; \
	} \
} while (0)

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

/* globals.log_fd should be line-buffered now */
#define log_and_output(args...) do { \
	if (globals.log_fd >= 0) { \
		dprintf(globals.log_fd, args); \
	} \
	output(args); \
} while (0)


#define tstamp_output(_fmt, ...) do { \
	char tstamp_buf[TSTAMP_BUF_SIZE]; \
	output("%s  " _fmt, tstamp(tstamp_buf), ##__VA_ARGS__); \
} while (0)
#define tstamp_log_and_output(_fmt, ...) do { \
	char tstamp_buf[TSTAMP_BUF_SIZE]; \
	log_and_output("%s  " _fmt, tstamp(tstamp_buf), ##__VA_ARGS__); \
} while (0)

#define thread_output(_fmt, ...) do { \
	tstamp_output("[%d / test proc %d / thread %d] " _fmt, thread_args->tid, proc_args->proc_num, thread_args->id, ##__VA_ARGS__); \
} while (0)

#define proc_output(_fmt, ...) do { \
	tstamp_output("[%d / test proc %d] " _fmt, proc_args->pid, proc_args->proc_num, ##__VA_ARGS__); \
} while (0)

#define global_output(_fmt, ...) do { \
	tstamp_log_and_output("[%d] " _fmt, globals.pid, ##__VA_ARGS__); \
} while (0)

/* which thread is responsible for the write which laid down data at this offset? */
#define WHOSE_WRITE(offset) ({ \
	int write_num = (offset - globals.off0) / globals.buf_size; \
	write_num % globals.thread_count; })

/* writes are performed by all threads simultaneously, operating in lock-step; on which
	round was the data at this offset written? */
#define WHICH_ROUND(offset) ({ \
	int write_num = (offset - globals.off0) / globals.buf_size; \
	write_num / globals.thread_count; })

#define SIZE_AFTER_WRITE_ROUND(round) ({ \
	min(globals.off0 + \
	(round * globals.buf_size * globals.thread_count), \
	globals.filesize })

#define WHICH_PAGE(offset) ({ \
	(offset / PAGE_SIZE_4K; })

#define BYTE_OF_WRITE(offset) ({ \
	(offset - globals.off0) % globals.buf_size; })

#define BYTE_OF_PAGE4K(offset) ({ \
	offset % PAGE_SIZE_4K; })


// may be necessary when testing OLD systems (RHEL 7 without glibc support */
//#ifndef __NR_memfd_create /* glibc doesn't have memfd_create? */
#ifndef MFD_CLOEXEC /* glibc doesn't have the necessary stuff? */

#if __x86_64__
#define __NR_memfd_create 319
#elif __aarch64__
#define __NR_memfd_create 279
#else
#error "Need syscall # for memfd_create"
#endif

# define SYS_memfd_create __NR_memfd_create

int memfd_create(const char *__name, unsigned int __flags) {
	return syscall(SYS_memfd_create, __name, __flags);
}
#endif /* don't have memfd_create */


#define try_sigaction(sig, sa, old_sa) do { \
	if ((sigaction(sig, sa, NULL)) < 0) { \
		global_output("error calling sigaction(%s): %m\n", STR(sig)); \
		ret++; \
		goto out; \
	} \
} while (0)
#define try_setitimer(which, timer, old_timer) do { \
	if ((setitimer(which, timer, old_timer)) < 0) { \
		global_output("error setting timer: %m\n"); \
		ret++; \
		goto out; \
	} \
} while (0)


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

#define find_nonzero_test(bits, a, b, len) do { \
	int ret; \
	if (len >= bits/8) { \
		if ((ret = PASTE(matchlen_u, bits)(a, b)) == (bits/8)) { \
			len -= bits/8; \
			a += bits/8; \
			continue; \
		} \
		return (a - _a) + ret; \
	} \
} while (0)
off_t find_nonzero(void *_a, size_t len) {
	union multi_access _b = { .u64[0] = 0 };
	void *a = _a, *b = &_b;
	while (len > 0) {
		find_nonzero_test(64, a, b, len);
		find_nonzero_test(32, a, b, len);
		find_nonzero_test(16, a, b, len);
		find_nonzero_test(8, a, b, len);
	}
	return (a - _a);
}

#pragma GCC pop_options

process_type my_process_type(void) {
	process_type *my_type;

	if ((my_type = (process_type *)pthread_getspecific(globals.process_type_key)))
		return *my_type;
	return -1;
}
int my_thread_id(void) {
	int *my_id;

	if ((my_id = (int *)pthread_getspecific(globals.thread_id_key)))
		return *my_id;
	return -1;
}
struct thread_args *my_thread_ptr(void) {
//	void *ptr = pthread_getspecific(proc_args->thread_key);
	int *my_id_ptr, my_id;

	if ((my_id_ptr = (int *)pthread_getspecific(globals.thread_id_key))) {
		my_id = *my_id_ptr;
		if (my_id >= globals.thread_count || my_id < -1)
			return NULL;
		return &proc_args->thread_args[my_id];
	}
	return NULL;
}
void *my_process_args(void) {
	return pthread_getspecific(globals.process_args_key);
}
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

int pthread_tbarrier_init(pthread_tbarrier_t *tbar,
		const pthread_barrierattr_t *restrict attr,
		int target_count, tbarrier_csncel_func_t cancel,
		struct timespec *freq) {

	int ret = 0;

	memset(tbar, 0, sizeof(pthread_tbarrier_t));
	pthread_mutex_init(&tbar->lock, NULL);
	pthread_mutex_lock(&tbar->lock);
	pthread_cond_init(&tbar->cond, NULL);

	tbar->target_count = target_count;
	tbar->threads_left = target_count;
	tbar->cycle = 0;

	if (freq) /* pass freq = NULL to use default of 1.0 seconds */
		tbar->freq = *freq;
	else
		tbar->freq = (struct timespec){ .tv_sec = 1, .tv_nsec = 0 };

	tbar->cancel = cancel;
	tbar->initialized = true;

	pthread_mutex_unlock(&tbar->lock);
	return ret;
}
int pthread_tbarrier_destroy(pthread_tbarrier_t *tbar) {
	int ret = EINVAL;

	if (!tbar->initialized)
		goto out;

	pthread_mutex_lock(&tbar->lock);
	pthread_cond_destroy(&tbar->cond);
	tbar->initialized = false;
	pthread_mutex_destroy(&tbar->lock);
	memset(tbar, 0, sizeof(*tbar));

	ret = EXIT_SUCCESS;
out:	
	return ret;
}

int pthread_tbarrier_wait(pthread_tbarrier_t *tbar) {
	uint32_t left, ret = 0;

	pthread_mutex_lock(&tbar->lock);

	if ((left = --tbar->threads_left) == 0) {

		tbar->threads_left = tbar->target_count;
		tbar->cycle++;

		pthread_cond_broadcast(&tbar->cond);

		ret = PTHREAD_BARRIER_SERIAL_THREAD;
		goto out;
	} else {
		uint32_t cycle = tbar->cycle;

		while (cycle == tbar->cycle) {
			struct timespec wait_stop_time;
			clock_gettime(CLOCK_REALTIME, &wait_stop_time);
			wait_stop_time.tv_sec += tbar->freq.tv_sec;
			wait_stop_time.tv_nsec += tbar->freq.tv_nsec;

			if (tbar->cancel && tbar->cancel()) {
				ret = PTHREAD_TBARRIER_CANCELED;
				break;
			}

			if ((ret = pthread_cond_timedwait(&tbar->cond, &tbar->lock, &wait_stop_time)) == 0)
				break; /* done waiting--we may continue */

			if (ret == ETIMEDOUT)
				continue; /* wait timed out... waiting again */

//			thread_output("%s - pthread_cond_timedwait returned error: %s\n", __func__, strerror(ret));
			tstamp_log_and_output("%s @%s:%d - [%d] pthread_cond_timedwait returned error: %s\n", __func__, __FILE__, __LINE__, gettid(), strerror(ret));
		}

		ret = 0;
		goto out;
	}
out:
	pthread_mutex_unlock(&tbar->lock);
	return ret;

}
uint32_t pthread_tbarrier_get_waiters(pthread_tbarrier_t *tbar) {
	uint32_t waiters;
	pthread_mutex_lock(&tbar->lock);
	waiters = tbar->target_count - tbar->threads_left;
	pthread_mutex_unlock(&tbar->lock);
	return waiters;
}
uint32_t pthread_tbarrier_get_cycle(pthread_tbarrier_t *tbar) {
	uint32_t cycle;
	pthread_mutex_lock(&tbar->lock);
	cycle = tbar->cycle;
	pthread_mutex_unlock(&tbar->lock);
	return cycle;
}
bool pthread_tbarrier_get_cancel(pthread_tbarrier_t *tbar) {
	bool cancel;
	pthread_mutex_lock(&tbar->lock);
	cancel = tbar->cancel;
	pthread_mutex_unlock(&tbar->lock);
	return cancel;
}


void handle_child_exit(int sig, siginfo_t *info, void *ucontext) {
	pid_t pid;
	int status, i;

	while ((pid = wait4(-1, &status, WNOHANG, NULL)) != -1) {
		bool found = false;
		if (pid == 0)
			return;

		for (i = 0 ; i < globals.proc_count ; i++) {
			if (globals.cpids[i] == pid) {
				if (globals.proc[i].replicated) {

					if (globals.proc[i].replicated > 1)
						global_output("test proc %d (pid %d) replicated the bug %d times on test #%d with device %d:%d inode %lu\n"
							"\tsee the logfile '%s/logs/test%d.log' for further details\n",
							i, pid, globals.proc[i].replicated, globals.proc[i].test_count,
							globals.proc[i].major, globals.proc[i].minor, globals.proc[i].inode,
							globals.canonical_base_dir_path, i);
					else
						global_output("test proc %d (pid %d) replicated the bug on test #%d with device %d:%d inode %lu\n",
							i, pid, globals.proc[i].test_count,
							globals.proc[i].major, globals.proc[i].minor, globals.proc[i].inode);

					__atomic_add_fetch(&globals.shared->replicated_count, 1, __ATOMIC_SEQ_CST);
					globals.shared->exit_test = exit_after_test; // tell everyone to exit at the end of this test
				} else if (WIFSIGNALED(status))
					global_output("test proc %d (pid %d) exiting with signal %d%s\n", i, pid,
						WTERMSIG(info->si_signo), WCOREDUMP(status) ? " and dumped core" : "");
				else if (globals.proc[i].exit_reason == exit_error)
					global_output("test proc %d (pid %d) exited on an error\n", i, pid);
				else if (globals.proc[i].exit_reason == exit_test_count) {
					global_output("test proc %d (pid %d) exited after performing %d tests\n", i, pid, globals.test_count);
					__atomic_add_fetch(&globals.shared->completed_count, 1, __ATOMIC_SEQ_CST);
				}

				globals.cpids[i] = 0;
				globals.proc[i].pid = 0;

				__atomic_sub_fetch(&globals.shared->running_count, 1, __ATOMIC_SEQ_CST);
				i = globals.proc_count;
				found = true;
			}
		}
		if (! found)
			global_output("unable to find exiting child pid %d (cue Billy Jean)\n", pid);
	} /* wait on any more children */
}
void handle_sig(int sig) {
	int i;

	if (sig == SIGPIPE) // can't do much with this
		return;

	global_output("caught signal %d; instructing test processes to exit\n", sig);

	if (__atomic_add_fetch(&globals.interrupt_count, 1, __ATOMIC_SEQ_CST) >= INTERRUPT_COUNT_REALLY_EXIT) {
		global_output("killing test processes forcibly\n");
		for (i = 0 ; i < globals.proc_count ; i++) {
			if (globals.cpids[i])
				kill(globals.cpids[i], SIGKILL);
		}
	} else
		globals.shared->exit_test = exit_now;
}

typedef enum { setup_handlers_prefork, setup_handlers_postfork, setup_handlers_disable_timer, setup_handlers_test_proc } setup_handlers_type;
int setup_handlers(setup_handlers_type handler_type);

uint64_t l1024(uint64_t x) {
	uint64_t r = __builtin_clzll(x);

	if (x < 1024)
		return 0;
	if (r == (sizeof(x) * 8UL))
		return 0;
	return ((sizeof(x) * 8UL) - 1 - r) / 10;
}
#define units_base 1024
static char *unit_strings[] = { " bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" };
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

void show_progress(int sig) {
	global_output("%d/%d running, writing: %d, verifying: %d, %lu tests started, replicated: %d\n",
		__atomic_load_n(&globals.shared->running_count, __ATOMIC_SEQ_CST), globals.proc_count,
		__atomic_load_n(&globals.shared->writing_count, __ATOMIC_SEQ_CST),
		__atomic_load_n(&globals.shared->verifying_count, __ATOMIC_SEQ_CST),
		__atomic_load_n(&globals.shared->test_count, __ATOMIC_SEQ_CST),
		__atomic_load_n(&globals.shared->replicated_count, __ATOMIC_SEQ_CST));
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


int write_into(const char *path, const char *val) {
	int ret = EXIT_SUCCESS, fd;

	errno = 0;
	if ((fd = open(path, O_RDWR)) < 0)
		{ output("error opening '%s': %m\n", path); ret++; }
	else if ((write(fd, val, strlen(val))) != strlen(val))
		{ output("error writing '%s' to '%s': %m\n", val, path); ret++; }

	if (close_fd(fd))
		ret++;

	return ret;
}
int write_into_at(int dfd, const char *path, const char *val) {
	int ret = 0, fd;

	if ((fd = openat(dfd, path, O_WRONLY)) < 0) {
		output("error opening '%s': %m\n", path);
		ret++;
	} else if ((write(fd, val, strlen(val))) != strlen(val)) {
		output("error writing '%s' to '%s': %m\n", val, path);
		ret++;
	} else if ((close_fd(fd)) < 0)
		ret++;
	return ret;
}
int write_cgroup_file(const char *path, uint64_t val) {
	char buf[32];

	snprintf(buf, sizeof(buf), "%lu", val);
	return write_into_at(globals.cgroup_fd, path, buf);
}
uint64_t read_cgroup_uint(const char *path) {
	char buf[32];
	uint64_t ret = 0;
	int fd = -1;
	ssize_t nchar;

	if ((fd = openat(globals.cgroup_fd, path, O_RDONLY)) < 0)
		output("error opening cgroup file '%s': %m\n", path);
	else if ((nchar = read(fd, buf, sizeof(buf))) < 0)
		output("error reading file '%s': %m\n", path);
	else {
		buf[sizeof(buf) - 1] = '\0';
		ret = strtoull(buf, NULL, 10);

		if (ret == ULLONG_MAX) {
			output("error parsing value '%s': %m\n", buf);
			ret = 0;
		}
	}

	close_fd(fd);

	return ret;
}

int init_cgroup(void) {
	struct statfs stfs;
	struct stat st;
	int ret = EXIT_FAILURE;

	if (! (statfs(CGROUP_PATH "/memory", &stfs))) {
		if (stfs.f_type == CGROUP_SUPER_MAGIC)
			globals.cgroup_vers = 1;
		else {
			global_output("filesystem type for '%s/memory' is not cgroup: %lx\n",
				CGROUP_PATH, stfs.f_type);
			goto out;
		}
	} else {
		if ((statfs(CGROUP_PATH, &stfs)) < 0) {
			global_output("error with statfs('%s'): %m\n", CGROUP_PATH);
			goto out;
		} else if (stfs.f_type == CGROUP2_SUPER_MAGIC)
			globals.cgroup_vers = 2;
		else {
			global_output("filesystem type for '%s' is not cgroup: %lx\n",
				CGROUP_PATH, stfs.f_type);
			goto out;
		}
	}

	if (globals.cgroup_vers == 1)
		globals.cgroup_path = CGROUP_V1_GROUP_PATH;
	else if (globals.cgroup_vers == 2)
		globals.cgroup_path = CGROUP_V2_GROUP_PATH;
	else {
		global_output("could not find cgroups filesystem at '%s'\n", CGROUP_PATH);
		goto out;
	}

	if ((lstat(globals.cgroup_path, &st)) < 0) {
		if (errno != ENOENT) {
			global_output("error with lstat('%s'): %m\n", globals.cgroup_path);
			goto out;
		}
	} else if ((rmdir(globals.cgroup_path)) < 0 && errno != EBUSY)
		global_output("error with rmdir('%s'): %m\n", globals.cgroup_path);

	if ((mkdir(globals.cgroup_path, 0755)) < 0 && errno != EEXIST) {
		global_output("error creating directory '%s': %m\n", globals.cgroup_path);
		goto out;
	}

	if ((globals.cgroup_fd = open(globals.cgroup_path, O_RDONLY|O_DIRECTORY)) < 0) {
		global_output("error opening cgroup path '%s': %m\n", globals.cgroup_path);
		goto out;
	}

	if (globals.cgroup_vers == 1) {
		// these are cgroups v1-specific
		if ((write_cgroup_file("memory.swappiness", 1)) != 0)
			global_output("error writing memory.swappiness: %m\n");
		else if ((write_cgroup_file("memory.oom_control", 1)) != 0)
			global_output("error writing memory.oom_control: %m\n");
		else
			ret = EXIT_SUCCESS;
	} else if (globals.cgroup_vers == 2)
		ret = EXIT_SUCCESS;
out:
	return ret;
}

int enter_cgroup(void) {
	if (write_cgroup_file("cgroup.procs", getpid()) == 0)
		return EXIT_SUCCESS;

	output("error entering cgroup\n");
	return EXIT_FAILURE;
}
void reduce_prio(void) { // not much we can do if these shenanigans fail
	int prio;

	if ((setpriority(PRIO_PROCESS, 0, globals.proc_prio)) < 0)
		output("error calling setpriority(): %m\n");
}

int set_sysctl(const char *path, const char *val) {
	int ret = EXIT_FAILURE, fd;

//	if ((fd = open("/proc/self/oom_score_adj", O_RDWR)) < 0) {
	if ((fd = open(path, O_RDWR)) < 0) {
		output("error opening '%s' for setting sysctl: %m\n", path);
	} else {
		char val[] = "-300\n";

		if ((write(fd, val, strlen(val))) < strlen(val)) {
			output("error setting sysctl '%s': %m\n", path);
		} else {
			output("set sysctl '%s' to '%s'\n", path, val);
		}
		if (close(fd) < 0) // shrug
			goto out;
	}
	ret = EXIT_SUCCESS;

out:
	return ret;
}


off_t proc_verify_file(off_t verify_start_offset, size_t verify_start_size) {
	size_t expected_size = verify_start_offset + verify_start_size;
	void *map = MAP_FAILED, *ptr;

	off_t verify_offset = verify_start_offset;
	size_t verify_size = verify_start_size;

	void *verify_start_addr;

	struct bug_results results;
	struct bug_result result;

	struct stat st;

	fstat(proc_args->fd, &st);

	if (st.st_size != expected_size) { // file size is expected to be offset + size
		proc_output("error with file size; expected 0x%lx (%lu), but size is 0x%lx (%lu)\n",
			expected_size, expected_size, st.st_size, st.st_size);

		results.count = ++proc_args->replicated;
		result = (struct bug_result){ .offset = st.st_size, .length = expected_size - st.st_size };

		pwrite(proc_args->memfd, &results, sizeof(results), 0);
		pwrite(proc_args->memfd, &result, sizeof(result),
			sizeof(struct bug_results) + sizeof(struct bug_result) * (proc_args->replicated - 1));
		goto out;
	}


	proc_output("verifying writes...  start offset: 0x%lx (%lu), size: 0x%lx (%lu), map length %lu\n",
		verify_offset, verify_offset, verify_size, verify_size, st.st_size);

	// just map the entire file, rather than from the page boundary before the verify offset and tracking offset offsets, etc.
	if ((map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, proc_args->fd, 0)) == MAP_FAILED) {
		proc_output("mmap failed while verifying recently-written file contents: %m\n");
		globals.verify_frequency = 0; // just verify at the end
		goto out;
	}


check_for_errors:
	verify_start_addr = map + verify_offset;

	if ((ptr = memchr(verify_start_addr, 0, verify_size))) {
		off_t valid_chars = ptr - verify_start_addr;
		size_t dump_bytes = min(DUMP_BYTE_COUNT, verify_offset + verify_size - valid_chars + (DUMP_BYTE_COUNT>>1));
		off_t this_error_offset = verify_offset + valid_chars, zero_count;


		proc_args->replicated++;


		if (dump_bytes > 0)
			hexdump("", verify_start_addr + valid_chars - (DUMP_BYTE_COUNT>>1), verify_offset + valid_chars - (DUMP_BYTE_COUNT>>1), dump_bytes);


		verify_offset = this_error_offset;
		verify_size -= valid_chars;

		if (verify_size <= 0) { /* shouldn't happen */
			proc_output("error: expected zero bytes, but remaining length indicates offset is at or beyond length of file: %ld?",
				verify_size);
			goto out;
		}

		verify_start_addr = map + verify_offset;
		zero_count = find_nonzero(verify_start_addr, verify_size);

		if (proc_args->memfd >= 0) {
			struct bug_results results = { .count = proc_args->replicated };
			struct bug_result result = { .offset = this_error_offset, .length = zero_count };

			/* we honestly can't do anything about errors here */
			pwrite(proc_args->memfd, &results, sizeof(results), 0);
			pwrite(proc_args->memfd, &result, sizeof(result),
				sizeof(struct bug_results) + sizeof(struct bug_result) * (proc_args->replicated - 1));
		}


		proc_output("  found zero bytes in file at offset 0x%lx (%lu) for length 0x%lx (%lu)\n",
			verify_offset, verify_offset, zero_count, zero_count);

		/* set up for next search */
		verify_offset += zero_count;
		verify_size -= zero_count;

		if (verify_size > 0)
			goto check_for_errors; /* search for more occurrences of the bug */

		goto out;
	} else
		proc_output("data at offset 0x%lx (%lu) for length 0x%lx (%lu) is valid\n",
			verify_offset, verify_offset, verify_size, verify_size);

out:
	if (map != MAP_FAILED && (munmap(map, st.st_size)) < 0)
		proc_output("munmap returned an error after verifying contents: %m\n");

	return proc_args->replicated;
}
bool need_verify(void) {
	int elapsed_rounds;

	if (proc_args->last_verified_size == proc_args->current_size)
		goto out_noverify;

	if (proc_args->write_round == proc_args->last_verify_round)
		goto out_noverify; /* nothing to be done, regardless of verify frequency */

	if (globals.shared->exit_test > exit_now_verify)
		goto out_noverify;

	if (globals.shared->exit_test == exit_now_verify)
		goto out_verify;

	if (globals.verify_frequency == 0) {
		if (proc_args->current_size >= globals.filesize)
			goto out_verify;
		goto out_noverify;
	}

	elapsed_rounds = proc_args->write_round - proc_args->last_verify_round;
	if (elapsed_rounds % globals.verify_frequency)
		goto out_noverify;

out_verify:
	return true;
out_noverify:
	return false;
}
void verify_file(off_t offset, size_t size) {
	if (! need_verify())
		goto out;

	__atomic_add_fetch(&globals.shared->verifying_count, 1, __ATOMIC_SEQ_CST);
	proc_verify_file(proc_args->last_verified_size, proc_args->current_size - proc_args->last_verified_size);
	__atomic_sub_fetch(&globals.shared->verifying_count, 1, __ATOMIC_SEQ_CST);


	proc_args->last_verify_round = proc_args->write_round;
	proc_args->last_verified_size = proc_args->current_size;

out:
	return;
}

/* attempt to malloc memory, assign; output error to 'scope'_output and goto 'out' on error */
#define try_malloc(size, scope, lock) ({ \
	void *addr; \
	if ((addr = malloc(size)) == NULL) { \
		PASTE(scope, _output)("%s %s:%d - error allocating memory: %m", \
			__func__, __FILE__, __LINE__); \
		goto out; \
	} \
	if (lock && (mlock2(addr, size, MLOCK_ONFAULT)) < 0) { \
		PASTE(scope, _output)("%s %s:%d - error locking memory: %m\n", \
			__func__, __FILE__, __LINE__); \
		goto out; \
	} \
	addr; \
})


void free_proc_paths(int i) {
	free_mem(globals.proc[i].name);
	free_mem(globals.proc[i].log_name);
}
int alloc_proc_paths(int i) {
	int ret = EXIT_FAILURE;

	if ((asprintf(&globals.proc[i].name, "test%d", i)) < 0) {
		ret = errno;
		globals.proc[i].name = NULL;
		goto out;
	}
	if ((asprintf(&globals.proc[i].log_name, "test%d.log", i)) < 0) {
		ret = errno;
		globals.proc[i].log_name = NULL;
		free_mem(globals.proc[i].name);
		goto out;
	}
	ret = EXIT_SUCCESS;
out:
	return ret;
}

bool proc_exit_test(void) {
	if (my_process_type() == process_type_proc) {
		if (__atomic_load_n(&proc_args->children_exited, __ATOMIC_SEQ_CST))
			proc_args->exit_test = true;
	}

	return proc_args ? proc_args->exit_test : false;
}

void *do_one_thread(void *args_ptr) {
	struct thread_args *thread_args = (struct thread_args *)args_ptr;
	process_type process_type = process_type_thread;

	thread_args->tid = gettid();
	pthread_setspecific(globals.process_type_key, (void *)&process_type);
	pthread_setspecific(globals.thread_id_key, (void *)&thread_args->id);
	pthread_setspecific(proc_args->thread_key, (void *)thread_args);
	pthread_setspecific(globals.process_args_key, (void *)thread_args);

	thread_output("alive, initial offset 0x%lx (%lu)\n", thread_args->offset, thread_args->offset);
	thread_args->buf = proc_args->thread_bufs[thread_args->id]; /* so we don't have to alloc & free each test... just set */

	if (! globals.shared->mem_max) { // one-time pause while the main process determines memory requirements
		__atomic_add_fetch(&globals.shared->threads_running, 1, __ATOMIC_SEQ_CST);
		while (!globals.shared->mem_max)
			sched_yield();
	}

	while (42) {
		size_t this_write_size = clamp(globals.filesize - thread_args->offset, 0UL, globals.buf_size);
		ssize_t written;

		pthread_tbarrier_wait(&proc_args->tbar1);
		if (proc_exit_test()) { // skip to the end!
			thread_output("exiting after writing %d times\n", thread_args->write_count);
			goto out;
		}

		if (this_write_size) {
			memset(thread_args->buf, fill_chars[thread_args->c], this_write_size);

			thread_output("write %d, offset 0x%lx (%lu), count 0x%lx (%lu), '%c' starting write\n",
				thread_args->write_count + 1, thread_args->offset, thread_args->offset,
				this_write_size, this_write_size, fill_chars[thread_args->c]);

			written = pwrite(proc_args->fd, thread_args->buf, this_write_size, thread_args->offset);


			if (written == this_write_size) {
				thread_output("write %d, offset 0x%lx (%lu), count 0x%lx (%lu), '%c' complete\n",
					thread_args->write_count + 1, thread_args->offset, thread_args->offset,
					this_write_size, this_write_size, fill_chars[thread_args->c]);

				thread_args->size = thread_args->offset + this_write_size;
				thread_args->write_count++;
			} else {
				 if (written == -1)
					thread_output("write %d, offset 0x%lx (%lu), count 0x%lx (%lu) failed with error: %m\n",
						thread_args->write_count + 1,  thread_args->offset, thread_args->offset,
						this_write_size, this_write_size);
				else
					thread_output("write %d, offset 0x%lx (%lu), count 0x%lx (%lu) had a short write of 0x%lx (%lu)\n",
						thread_args->write_count + 1,  thread_args->offset, thread_args->offset,
						this_write_size, this_write_size, written, written);
				__atomic_add_fetch(&proc_args->write_errors, 1, __ATOMIC_SEQ_CST); // write errors
				goto out_error;
			}
		}

		pthread_tbarrier_wait(&proc_args->tbar2); // keep all threads on same cycle, and let test process know it can verify

		if (this_write_size) {
			thread_args->offset += (globals.buf_size * globals.thread_count);
			thread_args->c = (thread_args->c + globals.thread_count) % FILL_LEN;

			if (thread_args->offset > globals.filesize)
				thread_args->offset = globals.filesize;
		}
		sched_yield();
	}

out:
	return NULL;

out_error:
	thread_output("exiting on error\n");
	thread_args->exit_reason = exit_error;
	__atomic_add_fetch(&proc_args->children_exited, 1, __ATOMIC_SEQ_CST);

	goto out;
}

int reap_thread(int id) {
	void *res;
	int ret = EAGAIN;

	if (proc_args->thread_args[id].thread) {
		if ((ret = pthread_tryjoin_np(proc_args->thread_args[id].thread, &res))) {
			if (ret == EBUSY) {
				ret = EAGAIN;
				goto out;
			}
			proc_output("tried to pthread_join(%d), but got error: %s\n", id, strerror(ret));
		} else {
			proc_args->thread_args[id].thread = 0;
			proc_output("thread %d exited\n", id);
			goto out;
		}
	} else
		ret = ENOENT;
out:
	return ret;
}

int reap_threads(int low, int high) { // inclusive
	int ret = EXIT_SUCCESS, i;

	proc_args->exit_test = true;

	while (42) {
		int live_threads = 0;

		for (i = low ; i <= high ; i++) {
			if (proc_args->thread_args[i].thread) {
				if ((ret = reap_thread(i))) {
					if (ret == EAGAIN || ret == EBUSY)
						live_threads++;
				}
			}
		}
		if (! live_threads)
			goto out;
		//proc_output("%d threads remain\n", live_threads);
		usleep(250);
	}

out:
	proc_output("all threads appear to have ended\n");

	return ret;
}
int launch_threads(void) {
	int ret = EXIT_FAILURE, i;

	for (i = 0; i < globals.thread_count; i++) {
		proc_args->thread_args[i].id = i;
		proc_args->thread_args[i].c = i % FILL_LEN; // in case we have more threads than fill chars
		proc_args->thread_args[i].offset = globals.off0 + (globals.buf_size * i);
		if ((ret = pthread_create(&proc_args->thread_args[i].thread, NULL, do_one_thread, &proc_args->thread_args[i])) != 0) {
			proc_output("pthread_create(%d) failed: %s\n", i, strerror(ret));
			proc_args->thread_args[i].thread = 0;

			proc_output("canceling all threads\n");
			goto out_cancel;
		}

		if (globals.shared->exit_test == exit_now) {
			proc_output("canceling test as instructed by main test process\n");
			goto out_cancel;
		}
	}
	ret = EXIT_SUCCESS;
out:
	proc_output("threads started; returning %d\n", ret);
	return ret;

out_cancel:
	reap_threads(0, globals.thread_count - 1);


	proc_output("all threads canceled\n");
	ret = EXIT_FAILURE;
	goto out;
}


// if some of the threads got an extra write() in (i.e. write failed due to
// 	error, etc.), need to reduce the file size to the largest size
// 	known to have been written by all threads
//
// for the file size, determine which thread would have written the
//     (offset + length) to cause the file to become that size
// with n being the number of times this thread has written:
//     all the threads with lower id must also have at least n writes;
//     all the threads with higher id must have at least n-1 writes
void truncate_test_file(void) {
	struct stat st;
	int ending_thread, write_count, i;
	size_t truncate_size;

	fstat(proc_args->fd, &st);

	truncate_size = min(st.st_size, proc_args->thread_args[0].size);

	ending_thread = (((truncate_size - globals.off0) / globals.buf_size) - 1) % globals.thread_count; // the thread that would have caused the file to be this size
	write_count = proc_args->thread_args[ending_thread].write_count;

	proc_output("file size is 0x%lx (%lu), last written by thread %d, which wrote %d times to file size 0x%lx (%lu)\n",
		st.st_size, st.st_size, ending_thread, write_count,
		proc_args->thread_args[ending_thread].size, proc_args->thread_args[ending_thread].size);

	proc_output("\n");

	int highest_with_min = 0;
	int min_wc = proc_args->thread_args[0].write_count;
	int max_wc = proc_args->thread_args[0].write_count;

	for (i = 1 ; i < globals.thread_count ; i++) {
		int this_wc = proc_args->thread_args[i].write_count;

		if (this_wc < min_wc) {
			min_wc = this_wc;
			highest_with_min = i;
		} else if (this_wc == min_wc) {
			highest_with_min = i;
		}

		if (this_wc > max_wc) {
			max_wc = this_wc;
		}
	}
	if (min_wc == max_wc) { /* easy; just pick the last one */
		truncate_size = proc_args->thread_args[globals.thread_count - 1].size;
	} else if (highest_with_min == 0) { /* easy; just pick the first one */
		truncate_size = proc_args->thread_args[0].size;
	} else {
		truncate_size = proc_args->thread_args[highest_with_min].size;
		for (i = 0 ; i < highest_with_min ; i++) {
			int this_wc = proc_args->thread_args[i].write_count;
			if (this_wc == min_wc + 1)
				truncate_size = proc_args->thread_args[i].size;
			else /* oh well */
				break;
		}
	}

	if (truncate_size < st.st_size) {
		proc_output("truncating file from 0x%lx (%lu) to size known to have completed: 0x%lx (%lu)\n",
			st.st_size, st.st_size, truncate_size, truncate_size);
		if ((ftruncate(proc_args->fd, truncate_size)) < 0) {
			proc_output("error truncating file: %m\n");
		}

		proc_output("target file size: %lu, file size: %lu, current_size (per test thread): %lu, truncated size: %lu\n",
			globals.filesize, st.st_size, proc_args->current_size, truncate_size);

		proc_args->current_size = truncate_size;
	} else {
//		proc_output("well... suppose I don't really need to truncate to its current size or larger (from %lu to %lu)\n", st.st_size, truncate_size);
	}
}



int do_one_test(void) {
	int ret = EXIT_FAILURE; /* whether the test run was successful, not whether we replicated the bug */
	struct stat st;
	int pthread_tbarrier_initialized = 0;

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

	proc_args->current_size = 0;
	proc_args->write_round = 0;
	proc_args->last_verify_round = 0;
	proc_args->last_verified_size = 0;


	{ // fill the first off0 bytes so that the only 0-byte contents are actually the bug
		int ret2;

		memset(proc_args->thread_bufs[0], fill_chars[FILL_LEN - 1], globals.off0); // reuse the buf for thread 0
		if ((ret2 = pwrite(proc_args->fd, proc_args->thread_bufs[0], globals.off0, proc_args->current_size)) != globals.off0) {
			if (ret2 == -1)
				proc_output("error writing initial off0 bytes to test file: %m\n");
			else
				proc_output("short write for initial off0 bytes (tried %lu, only %d written)\n",
					globals.off0, ret2);
			goto out;
		}
	}
	proc_args->current_size += globals.off0;

	memset(proc_args->thread_args, 0, sizeof(struct thread_args) * globals.thread_count);
	__atomic_store_n(&proc_args->children_exited, 0, __ATOMIC_SEQ_CST);
	proc_args->exit_test = false;


	if ((pthread_tbarrier_init(&proc_args->tbar1, NULL, globals.thread_count + 1, &proc_exit_test, NULL))) {
		proc_output("error calling pthread_tbarrier_init(): %m\n");
		goto out;
	}
	pthread_tbarrier_initialized++;
	if ((pthread_tbarrier_init(&proc_args->tbar2, NULL, globals.thread_count + 1, &proc_exit_test, NULL))) {
		proc_output("error calling pthread_tbarrier_init(): %m\n");
		goto out;
	}
	pthread_tbarrier_initialized++;


	if ((ret = launch_threads()) != EXIT_SUCCESS)
		goto out;


	while (42) {
		size_t this_write_size = clamp(globals.buf_size * globals.thread_count, 0UL, max(globals.filesize - proc_args->current_size, 0UL));

		__atomic_add_fetch(&globals.shared->writing_count, 1, __ATOMIC_SEQ_CST);
		pthread_tbarrier_wait(&proc_args->tbar1);
		if (proc_args->exit_test) {
			__atomic_sub_fetch(&globals.shared->writing_count, 1, __ATOMIC_SEQ_CST);
			break;
		}

		pthread_tbarrier_wait(&proc_args->tbar2); // need to make sure everyone's write has completed
		__atomic_sub_fetch(&globals.shared->writing_count, 1, __ATOMIC_SEQ_CST);

		if (__atomic_load_n(&proc_args->write_errors, __ATOMIC_SEQ_CST)) { // write errors
			proc_args->exit_test = true;
		} else { // no write errors
			proc_args->write_round++;
			proc_args->current_size += this_write_size;
			if (need_verify())
				verify_file(proc_args->current_size, this_write_size);
				
		}
		if (proc_args->replicated)
			proc_args->exit_test = true;

		if (globals.shared->exit_test == exit_now)
			proc_args->exit_test = true;
		
//		if (__atomic_load_n(&proc_args->interrupted, __ATOMIC_SEQ_CST) || proc_args->current_size >= globals.filesize)
//			proc_args->exit_test = true;
		if (proc_args->current_size >= globals.filesize)
			proc_args->exit_test = true;
		sched_yield();
	}


	ret = EXIT_SUCCESS;

	reap_threads(0, globals.thread_count - 1);

	truncate_test_file(); // some processes may have been rudely interrupted or completed only partial writes
	close_fd(proc_args->fd);

//	if (proc_args->last_verify_round < proc_args->write_round && !__atomic_load_n(&proc_args->interrupted, __ATOMIC_SEQ_CST)) {
	if (need_verify()) {
		proc_output("test #%d verifying file contents\n", proc_args->test_count);

		verify_file(0, globals.filesize);

		if (proc_args->replicated)
			ret = EXIT_SUCCESS;
		else
			proc_output("verification succeeded; no errors found\n");
	}

out:

	if (pthread_tbarrier_initialized == 2 && pthread_tbarrier_destroy(&proc_args->tbar2))
		proc_output("error calling pthread_tbarrier_destroy(): %m\n"); // don't consider this fatal
	if ((pthread_tbarrier_initialized && pthread_tbarrier_destroy(&proc_args->tbar1)))
		proc_output("error calling pthread_tbarrier_destroy(): %m\n"); // don't consider this fatal

	close_fd(proc_args->fd);

	return ret == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

void proc_sig_handler(int sig) {
	if (sig != SIGPIPE)
		proc_output("in the proc sig handler with signal %d\n", sig);
	__atomic_add_fetch(&proc_args->interrupted, 1, __ATOMIC_SEQ_CST);
}

int open_memfd(int proc_num) {
	char *name = NULL;
	int fd;

	asprintf(&name, "test%d", proc_num);

	if ((fd = memfd_create(name, 0)) < 0) {
		global_output("error creating memfd for process %d: %m\n", proc_num);
	}
	free_mem(name);

	return fd;
}

int do_one_proc(int proc_num) {
        process_type process_type = process_type_proc;
	int ret = EXIT_FAILURE, minusone = -1, i;
	int pthread_keys_created = 0;

	proc_args = &globals.proc[proc_num];
	proc_args->pid = getpid();

	pthread_setspecific(globals.process_type_key, (void *)&process_type);
	pthread_setspecific(globals.thread_id_key, (void *)&minusone);
	pthread_setspecific(globals.proc_id_key, (void *)&proc_args->proc_num);
	pthread_setspecific(globals.process_args_key, (void *)proc_args);

	reduce_prio();
	if (enter_cgroup() != EXIT_SUCCESS) {
		proc_output("exiting due to failure to join cgroup\n");
		goto out; // yeah, this is kinda important to make the test work
	}

	alloc_proc_paths(proc_num);


	for (i = 0 ; i < proc_num ; i++) /* only need to close the ones opened before we were forked */
		close(globals.proc[i].memfd); // can't close_fd(), since that would wipe out the stored fd

	setup_handlers(setup_handlers_test_proc);

	proc_output("alive\n");

	if ((proc_args->log_fd = openat(globals.log_dir_fd, proc_args->log_name, O_CREAT|O_WRONLY, 0644)) < 0) {
		proc_output("error opening logfile '%s/logs/%s': %m\n", globals.base_dir_path, proc_args->log_name);
		goto out;
	}
	lseek(proc_args->log_fd, 0, SEEK_END);
	if ((proc_args->log_FILE = fdopen(proc_args->log_fd, "a")) == NULL)
		proc_output("unable to reopen log fd: %m\n");
	else
		if ((globals.log_FILE = fdopen(globals.log_fd, "a")) == NULL)
			global_output("unable to reopen log fd: %m\n");
		else
			setvbuf(proc_args->log_FILE, NULL, _IONBF, 0); // try going commando

	if ((dup3(proc_args->log_fd, fileno(stdout), 0)) < 0) {
		global_output("%s  [%d] error replacing stdout: %m\n", tstamp(tstamp_buf), proc_args->pid);
		goto out;
	}
	if ((dup3(proc_args->log_fd, fileno(stderr), 0)) < 0) {
		global_output("%s  [%d] error replacing stderr: %m\n", tstamp(tstamp_buf), proc_args->pid);
		goto out;
	}

	proc_output("alive\n"); // repeat ourselves, now that we've got our own logfile

	pthread_key_create(&proc_args->thread_id_key, NULL);
	pthread_keys_created++;
	pthread_key_create(&proc_args->thread_key, NULL);
	pthread_keys_created++;


	proc_args->thread_args = try_malloc(sizeof(struct thread_args) * globals.thread_count, proc, true);
	proc_args->thread_bufs = try_malloc(sizeof(char *) * globals.thread_count, proc, true);
	for (i = 0 ; i < globals.thread_count ; i++)
		proc_args->thread_bufs[i] = try_malloc(globals.buf_size, proc, false);

	for (proc_args->test_count = 1 ; proc_args->test_count <= globals.test_count ; proc_args->test_count++) {

retry_test:
		proc_args->write_round = 0;
		proc_args->last_verify_round = 0;
		proc_args->last_verified_size = 0;
		proc_args->replicated = 0;
		proc_args->exit_test = false;
		proc_args->write_errors = 0;
		proc_args->children_exited = 0;
		proc_args->interrupted = 0;


		if (proc_args->interrupted || globals.shared->exit_test) { /* global or per-proc exit flag */
			proc_output("exiting as requested\n");
			goto out;
		}

		__atomic_add_fetch(&globals.shared->test_count, 1,  __ATOMIC_SEQ_CST); /* update the global stat */

		if ((ret = do_one_test()) == EXIT_FAILURE) {
			proc_output("error while running test\n");

			if (!proc_args->replicated && proc_args->write_errors &&
				! proc_args->interrupted && globals.shared->exit_test <= exit_after_test) {

				struct timespec sleep_time = PROC_RESTART_HOLDOFF;

				proc_output("delaying briefly before re-launching test\n");
				nanosleep(&sleep_time, NULL);
				proc_output("restarting test #%d due to write errors\n", proc_args->test_count);


				goto retry_test;
			}
			break;
		}

		if (proc_args->replicated) {
			proc_output("test proc %d replicated the bug %d time%s on test #%d with device %d:%d inode %lu\n",
				proc_args->proc_num, proc_args->replicated,
				proc_args->replicated == 1 ? "" : "s", proc_args->test_count,
				proc_args->major, proc_args->minor, proc_args->inode);
			ret = EXIT_SUCCESS;
			break;
		}
	}
	if (proc_args->replicated)
		proc_args->exit_reason = exit_replicated;
	else if (proc_args->test_count > globals.test_count)
		proc_args->exit_reason = exit_test_count;
	else if (proc_args->write_errors)
		proc_args->exit_reason = exit_error;

out:

	close(proc_args->memfd);
	close_fd(proc_args->fd);
	if (proc_args->thread_bufs) {
		for (i = 0 ; i < globals.thread_count ; i++) {
			free_mem(proc_args->thread_bufs[i]);
		}
	}
	free_mem(proc_args->thread_bufs);
	free_mem(proc_args->thread_args);
	free_proc_paths(proc_args->proc_num);

	if (pthread_keys_created == 2 && pthread_key_delete(proc_args->thread_key))
		proc_output("error calling pthread_key_delete() for thread_key: %m\n");
	if (pthread_keys_created && pthread_key_delete(proc_args->thread_id_key))
		proc_output("error calling pthread_key_delete() for thread_id_key: %m\n");

	close_FILE(proc_args->log_FILE, proc_args->log_fd);
	dup3(globals.stdout_fd, fileno(stdout), 0); // restore stdout, close log
	dup3(globals.stderr_fd, fileno(stderr), 0); // restore stderr

	return ret;
}

int usage(int ret) {
	output("usage; %s [<options>] <base_directory_path>\n", globals.exe);

	output("\t-s | --file_size=<size>\t\t(default: %llu, min: %llu, max: %llu)\n", DEFAULT_FILE_SIZE, MIN_FILE_SIZE, MAX_FILE_SIZE);

	output("\t-b | --buffer_size=<size>\t\t(default: %llu, min: %llu, max: %llu)\n", DEFAULT_BUF_SIZE, MIN_BUF_SIZE, MAX_BUF_SIZE);
	output("\t-p | --processes=<process_count>\t(default - number of online cpus: %d, max: %d)\n", globals.online_cpus, MAX_PROC_COUNT);
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

	output("\t-V | --verify=<number>\t\t\thow frequently to verify the written data\n");
	output("\t\t\t\t (i.e. every '1', '2', '3' writes; default: 0 == check at end only)\n");
	output("\t-m | --cgroup_memry=<size>\t\t(default: calculated from semi-arbitrary factors)\n");

	return ret;
}
#define msg_usage(ret, args...) ({ \
	output(args); \
	usage(ret); \
})

int setup_handlers(setup_handlers_type handler_type) {
	struct itimerval timer;
	struct sigaction sa;
	int ret = 0;

	memset(&sa, 0, sizeof(sa));

	if (handler_type == setup_handlers_prefork) { /* pre-forki, block SIGCHLD */
		sigemptyset(&sa.sa_mask);
		sigaddset(&sa.sa_mask, SIGCHLD);
		if ((sigprocmask(SIG_BLOCK, &sa.sa_mask, NULL)) < 0) {
			global_output("error blocking SIGCHLD: %m\n");
			ret++;
			goto out; /* considering this fatal */
		}
	} else if (handler_type == setup_handlers_postfork) { /* after forking */
		/* setup handler for various signals */
		sigfillset(&sa.sa_mask);
		sa.sa_flags = 0;
		sa.sa_handler = &handle_sig;
		try_sigaction(SIGINT, &sa, NULL);
		try_sigaction(SIGTERM, &sa, NULL);
		try_sigaction(SIGPIPE, &sa, NULL);
		try_sigaction(SIGABRT, &sa, NULL);
		try_sigaction(SIGHUP, &sa, NULL);
		try_sigaction(SIGQUIT, &sa, NULL);

		/* setup timer for updates */
		timer.it_value = timer.it_interval = globals.update_timer;
		sigfillset(&sa.sa_mask);
		sa.sa_handler = &show_progress;
		try_sigaction(SIGALRM, &sa, NULL);
		try_setitimer(ITIMER_REAL, &timer, NULL);

		/* setup handler for SIGCHLD */
		sigfillset(&sa.sa_mask);
		sa.sa_handler = NULL;
		sa.sa_sigaction = &handle_child_exit;
		try_sigaction(SIGCHLD, &sa, NULL);

		/* unblock SIGCHLD */
		sigemptyset(&sa.sa_mask);
		sigaddset(&sa.sa_mask, SIGCHLD);
		if ((sigprocmask(SIG_UNBLOCK, &sa.sa_mask, NULL)) < 0)
			global_output("error unblocking SIGCHLD: %m\n"); /* is this fatal? */
	} else if (handler_type == setup_handlers_disable_timer) { /* disable the timer */
		timer.it_value = timer.it_interval = (struct timeval){ .tv_sec = 0, .tv_usec = 0 };
		try_setitimer(ITIMER_REAL, &timer, NULL);
	} else if (handler_type == setup_handlers_test_proc) { /* test process */

		/* allow the process to handle its own signals */
		sigfillset(&sa.sa_mask);
		sa.sa_flags = 0;
		sa.sa_handler = &proc_sig_handler;
		try_sigaction(SIGINT, &sa, NULL);
		try_sigaction(SIGTERM, &sa, NULL);
		try_sigaction(SIGPIPE, &sa, NULL);
		try_sigaction(SIGABRT, &sa, NULL);
		try_sigaction(SIGHUP, &sa, NULL);
		try_sigaction(SIGQUIT, &sa, NULL);
	}
out:
	return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

struct linux_dirent64 {
	ino64_t		d_ino;    /* 64-bit inode number */
	off64_t		d_off;    /* 64-bit offset to next structure */
	unsigned short	d_reclen; /* Size of this dirent */
	unsigned char	d_type;   /* File type */
	char		d_name[]; /* Filename (null-terminated) */
};

size_t reclaim_disk(int _dfd, const char *reclaim_path) {
	struct linux_dirent64 *de;
	char *getdents_buf = NULL, *bpos;
	int nread;
	size_t reclaimable = 0, reclaimed = 0, reclaimed_reuse = 0, reclaim_failed = 0;
	int unreclaimable_objects = 0, dfd = -1;
	struct stat st;

	global_output("attempting to reclaim disk space in the test directory '%s/%s'\n",
		globals.canonical_base_dir_path, reclaim_path);

	getdents_buf = try_malloc(GETDENTS_BUF_SIZE, global, false);

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

				if (filenum == ULONG_MAX && errno == ERANGE) { /* overflow */
					reclaimable += st.st_size; /* could be reclaimed, but we're not doing so, since we don't know what it is */
					continue;
				}
				if (*p != '\0' && strcmp(p, ".log")) { /* filename not test###.log */
					reclaimable += st.st_size; /* could be reclaimed, but we're not doing so, since we don't know what it is */
					continue;
				}

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

int check_free_disk(void) {
	off_t total_disk_required = globals.filesize * globals.proc_count;
	char *total_disk_required_str = byte_units(total_disk_required);
	char *filesize_str = byte_units(globals.filesize);
	char *buf_size_str = byte_units(globals.buf_size);
	struct statfs stfs;
	int ret = EXIT_FAILURE;

	global_output("test running on '%s' arch '%s' kernel '%s'\n", globals.uts.nodename, globals.uts.machine, globals.uts.release);
	global_output("base directory for testing is '%s'\n", globals.canonical_base_dir_path);

	global_output("size of each testfile is 0x%lx (%lu - %s) bytes, and buffer size will be 0x%lx (%lu - %s)\n",
		globals.filesize, globals.filesize, filesize_str, globals.buf_size, globals.buf_size, buf_size_str);
	free_mem(filesize_str);
	free_mem(buf_size_str);

	global_output("initial offset is 0x%lx (%ld)\n", globals.off0, globals.off0);
	global_output("creating %d test processes, each having %d threads\n", globals.proc_count, globals.thread_count);

	output("\n");
	global_output("tests will require approximately %lu bytes (%s) in the test directory (%s/testfiles)\n",
		total_disk_required, total_disk_required_str, globals.canonical_base_dir_path);

	/* make sure we have enough disk space on this puppy */
	if ((fstatfs(globals.testfile_dir_fd, &stfs)) < 0) {
		global_output("error calling fstatfs() to verify free space: %m\n");
		goto out;
	}
	if (total_disk_required > stfs.f_blocks * stfs.f_bsize) { /* can't even reclaim and have enough */
		char *size_total_str = byte_units(stfs.f_blocks * stfs.f_bsize);

		global_output("ERROR: disk space required (%lu - %s) exceeds total disk space (%lu - %s) at that location (%s)\n",
			total_disk_required, total_disk_required_str, stfs.f_blocks * stfs.f_bsize, size_total_str,
			globals.canonical_base_dir_path);

		free_mem(size_total_str);
		goto out;
	}

	reclaim_disk(globals.testfile_dir_fd, "testfiles"); /* remove existing testfiles */
	reclaim_disk(globals.log_dir_fd, "logs"); /* remove existing logfiles */

	if ((fstatfs(globals.testfile_dir_fd, &stfs)) < 0) {
		global_output("error calling fstatfs() to verify free space: %m\n");
		goto out;
	}
	if (total_disk_required > stfs.f_bfree * stfs.f_bsize) {
		char *size_avail_str = byte_units(stfs.f_bfree * stfs.f_bsize);
		char *size_short_str = byte_units(total_disk_required - (stfs.f_bfree * stfs.f_bsize));

		global_output("ERROR: disk space required (%lu - %s) exceeds available disk space (%lu - %s) at that location (%s) by at least %lu (%s)\n",
			total_disk_required, total_disk_required_str, stfs.f_bfree * stfs.f_bsize, size_avail_str, globals.canonical_base_dir_path,
			total_disk_required - (stfs.f_bfree * stfs.f_bsize), size_short_str);

		free_mem(size_avail_str);
		free_mem(size_short_str);

		goto out;
	}
	log_and_output("\n");

	ret = EXIT_SUCCESS;

out:
	free_mem(total_disk_required_str);
	return ret;

}

/* return zero if this was the child process, non-zero if we're still the parent process */
int start_test_proc(int id) {
	pid_t cpid;
	int ret = 0;

	globals.proc[id].proc_num = id;
	globals.proc[id].memfd = open_memfd(id);
	globals.proc[id].exit_reason = not_exiting;

	if ((cpid = fork()) == 0) {
		do_one_proc(id);
		goto out;
	} else if (cpid > 0) {
		globals.cpids[id] = cpid;
		globals.proc[id].pid = cpid;
		global_output("forked test proc %d as pid %d\n", id, globals.proc[id].pid);
		__atomic_add_fetch(&globals.shared->running_count, 1, __ATOMIC_SEQ_CST);
		ret = cpid;
	} else {
		global_output("error forking test proc %d (returned %d): %m\n", id, globals.proc[id].pid);
		ret = 1;
	}
out:
	return ret;
}

int setup_cgroup_limits(void) {
	int ret = EXIT_FAILURE;

	if (! globals.shared->mem_max) { // one-time thing
		char *current_file = CGROUP_V1_CURRENT_USAGE_FILE;
		char *mem_min_str = NULL, *mem_high_str = NULL, *mem_max_str = NULL;
		char *high_file = CGROUP_V1_HIGH_FILE;
		char *max_file = CGROUP_V1_MAX_FILE;

		if (globals.cgroup_vers == 2) {
			current_file = CGROUP_V2_CURRENT_USAGE_FILE;
			high_file = CGROUP_V2_HIGH_FILE;
			max_file = CGROUP_V2_MAX_FILE;
		}

//		while (__atomic_load_n(&globals.shared->threads_running, __ATOMIC_SEQ_CST) < (globals.thread_count * globals.proc_count))
//			sched_yield();

//		pthread_tbarrier_wait(&globals.shared->tbar); // make sure everyone is started

		global_output("\n\n");

		globals.shared->mem_min = read_cgroup_uint(current_file);
		mem_min_str = byte_units(globals.shared->mem_min);
		global_output("current/minimum memory usage: %s\n", mem_min_str);

		globals.shared->mem_high = globals.shared->mem_min + (globals.shared->mem_min / 2);
		mem_high_str = byte_units(globals.shared->mem_high);
		global_output("setting cgroup 'high' memory size: %s\n", mem_high_str);
		if ((write_cgroup_file(high_file, globals.shared->mem_high)) != 0) {
			global_output("error writing memory 'high' limit: %m\n");
			goto out;
		}

		globals.shared->mem_max = globals.shared->mem_min * 2;
		mem_max_str = byte_units(globals.shared->mem_max);
		global_output("setting cgroup 'max' memory size: %s\n", mem_max_str);
		if ((write_cgroup_file(max_file, globals.shared->mem_max)) != 0) {
			global_output("error writing memory 'max' limit: %m\n");
			goto out;
		}

		global_output("\n\n");

		free_mem(mem_min_str);
		free_mem(mem_high_str);
		free_mem(mem_max_str);
	}
out:
	return ret;
}


int do_testing() {
	process_type process_type = process_type_main;
	sigset_t signal_mask;
	int ret = EXIT_FAILURE, i;

	setpriority(PRIO_PROCESS, 0, -10);

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
			globals.canonical_base_dir_path); // I suppose we don't have to consider this fatal
	} else {
		if ((globals.log_FILE = fdopen(globals.log_fd, "a")) == NULL)
			global_output("unable to reopen log fd: %m\n"); // not super fatal either
		else
			setvbuf(globals.log_FILE, NULL, _IONBF, 0); // try setting unbuffered
	}


	if ((mkdirat(globals.base_dir_fd, "testfiles", 0777)) && errno != EEXIST) {
		global_output("error creating testfile dir '%s/testfiles': %m\n", globals.canonical_base_dir_path);
		goto out;
	}
	if ((globals.testfile_dir_fd = openat(globals.base_dir_fd, "testfiles", O_RDONLY|O_DIRECTORY)) < 0) {
		global_output("error opening testfile dir '%s/testfiles': %m\n", globals.canonical_base_dir_path);
		goto out;
	}


	if ((globals.proc = mmap(NULL, sizeof(struct proc_args) * globals.proc_count, PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
		global_output("error mapping memory for processes: %m\n");
		goto out;
	}
	if ((globals.shared = mmap(NULL, sizeof(struct shared_struct), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
		global_output("error mapping memory for shared state: %m\n");
		goto out;
	}
	globals.cpids = try_malloc(sizeof(pid_t) * globals.proc_count, global, true);

	if ((init_cgroup()) != EXIT_SUCCESS)
		goto out;


	globals.cpids = try_malloc(sizeof(pid_t) * globals.proc_count, global, true);

//	if ((setup_cgroup()) != EXIT_SUCCESS)
//		goto out;

	pthread_setspecific(globals.process_type_key, (void *)&process_type);

	/* open log dir */
	if ((mkdirat(globals.base_dir_fd, "logs", 0777)) && errno != EEXIST) {
		global_output("error creating log dir '%s/logs': %m\n", globals.canonical_base_dir_path);
		goto out;
	}
	if ((globals.log_dir_fd = openat(globals.base_dir_fd, "logs", O_RDONLY|O_DIRECTORY)) < 0) {
		global_output("error opening log dir '%s/logs': %m\n", globals.canonical_base_dir_path);
		goto out;
	}
	globals.shared->exit_test = no_exit;


	if ((ret = check_free_disk()) != EXIT_SUCCESS)
		goto out;

	if (setup_handlers(setup_handlers_prefork) != EXIT_SUCCESS) /* call #0 - block SIGCHLD, etc. */
		goto out;

	show_progress(0);
	for (i = 0 ; i < globals.proc_count ; i++) {
		if ((start_test_proc(i)) == 0) {
			goto out;
		}
	}

	show_progress(0);

	setup_handlers(setup_handlers_postfork);

	sigfillset(&signal_mask);
	sigdelset(&signal_mask, SIGCHLD);
	sigdelset(&signal_mask, SIGINT);
	sigdelset(&signal_mask, SIGPIPE);
	sigdelset(&signal_mask, SIGABRT);
	sigdelset(&signal_mask, SIGHUP);
	sigdelset(&signal_mask, SIGQUIT);
	sigdelset(&signal_mask, SIGALRM);

	while (42) {
		sigsuspend(&signal_mask);

		if (!globals.shared->mem_max && __atomic_load_n(&globals.shared->threads_running, __ATOMIC_SEQ_CST) == (globals.thread_count * globals.proc_count))
				setup_cgroup_limits();

		if (globals.shared->exit_test > no_exit && __atomic_load_n(&globals.shared->running_count, __ATOMIC_SEQ_CST) == 0)
			break;
		if ((__atomic_load_n(&globals.shared->replicated_count, __ATOMIC_SEQ_CST)) > 0)
			globals.shared->exit_test = max(exit_after_test, globals.shared->exit_test);


		// re-launch a test process, if it's exited on an error
		if (globals.shared->exit_test == no_exit) {
			int count = 0;
			count += __atomic_load_n(&globals.shared->running_count, __ATOMIC_SEQ_CST);
			count += __atomic_load_n(&globals.shared->replicated_count, __ATOMIC_SEQ_CST);
			count += __atomic_load_n(&globals.shared->completed_count, __ATOMIC_SEQ_CST);

			/* not supposed to exit just yet, but some process(es) has(have) */
			if (count < globals.proc_count) {
				for (i = 0 ; i < globals.proc_count ; i++) {
					if (globals.proc[i].pid == 0 &&
						globals.proc[i].exit_reason == exit_error &&
						start_test_proc(i) == 0)
						goto out;
				}
			}
		}
	}

	setup_handlers(setup_handlers_disable_timer); /* disable the timer */

	show_progress(0);
	int total_errors = 0;

	if (globals.shared->replicated_count) {
		log_and_output("==========================================================\n");
		log_and_output("replicated the bug %d time%s\n",
			globals.shared->replicated_count, 
			globals.shared->replicated_count == 1 ? "" : "s");
		for (i = 0 ; i < globals.proc_count ; i++) {
			if (globals.proc[i].replicated) {

				log_and_output("%s/testfiles/test%d - device %d:%d inode %lu - %d error%s\n",
					globals.canonical_base_dir_path, i,
					globals.proc[i].major, globals.proc[i].minor, globals.proc[i].inode,
					globals.proc[i].replicated, globals.proc[i].replicated == 1 ? "" : "s");

				if (globals.proc[i].memfd >= 0) {
					struct bug_results results;
					int j;

					if ((ret = pread(globals.proc[i].memfd, &results, sizeof(results), 0)) < sizeof(results)) {
						log_and_output("error reading bug count: %m\n");
						results.count = globals.proc[i].replicated;
					}
					for (j = 0 ; j < results.count ; j++) {
						struct bug_result result;
						off_t end_offset;

						if ((ret = pread(globals.proc[i].memfd, &result, sizeof(result), sizeof(results) + (j * sizeof(result)))) < sizeof(result)) {
							log_and_output("error reading result %d: %m\n", j + 1);
							continue;
						}

						total_errors++;

						end_offset = result.offset + result.length - 1;

						log_and_output("\t%3d - offset 0x%lx (%lu) - 0x%lx (%lu) - length: %lu\n",
							j + 1, result.offset, result.offset,
							end_offset, end_offset,
							result.length);

						if (result.length > globals.buf_size) {
							log_and_output("length of the zero bytes is unexpectedly longer than the size of a buffer\n");
						} else {
							log_and_output("\t\tstart is page %lu, offset %lu; byte %ld of write %d by thread %d\n",
								result.offset / PAGE_SIZE_4K,
								BYTE_OF_PAGE4K(result.offset),
								BYTE_OF_WRITE(result.offset),
								WHICH_ROUND(result.offset),
								WHOSE_WRITE(result.offset));

							log_and_output("\t\tend is page %lu, offset %lu; byte %ld of write %d by thread %d\n",
								(end_offset) / PAGE_SIZE_4K,
								BYTE_OF_PAGE4K(end_offset),
								BYTE_OF_WRITE(end_offset),
								WHICH_ROUND((end_offset)),
								WHOSE_WRITE((end_offset)));
						}

						log_and_output("\n");
					}

					close(globals.proc[i].memfd);

//					if (i < (globals.proc_count - 1))
//						log_and_output("\n");
				}
			}
		} /* for each test proc */
		if (globals.shared->replicated_count)
			log_and_output("%d total error%s in %d total test file%s\n",
				total_errors, total_errors == 1 ? "" : "s",
				globals.shared->replicated_count,
				globals.shared->replicated_count == 1 ? "" : "s");
	} else
		log_and_output("did not replicate the bug\n");
out:
	close_fd(globals.testfile_dir_fd);
	close_fd(globals.log_dir_fd);
	close_fd(globals.base_dir_fd);
	close_FILE(globals.log_FILE, globals.log_fd);
//	close_fd(globals.log_fd); /* closing the log_FILE will close this as well */

	if (gettid() == globals.pid) {
		struct timespec run_time;

		if (globals.proc) {
			for (i = 0 ; i < globals.proc_count ; i++)
				close(globals.proc[i].memfd); /* ignore errors */

			munmap(globals.proc, sizeof(struct proc_args) * globals.proc_count);
		}
		if (globals.shared)
			munmap(globals.shared, sizeof(struct shared_struct) + (sizeof(uint64_t) * globals.proc_count));
		free_mem(globals.cpids);

		log_and_output("results logged to %s/log.out\n", globals.canonical_base_dir_path);

		clock_gettime(CLOCK_REALTIME, &globals.end_time);
		run_time = (struct timespec){
			.tv_sec = globals.end_time.tv_sec - globals.start_time.tv_sec,
			.tv_nsec = globals.end_time.tv_nsec - globals.start_time.tv_nsec };

		while (run_time.tv_nsec < 0) {
			run_time.tv_nsec += 1000000000ULL;
			run_time.tv_sec--;
		}
		log_and_output("total runtime: %lu.%09lu seconds\n",
			run_time.tv_sec, run_time.tv_nsec);
	}

	// empty out the cgroup & get rid of it
//	rmdir(MEMORY_CGROUP_PATH "/" MEMORY_CGROUP_NAME);

	return ret;
}

void do_global_init(char *exe) {
	memset(&globals, 0, sizeof(globals));

	globals.exe = exe;
	globals.page_size = sysconf(_SC_PAGESIZE);
	globals.online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	globals.main_prio = getpriority(PRIO_PROCESS, 0);
	globals.proc_prio = globals.main_prio + 5;
	globals.pid = getpid();

	globals.proc_count = globals.online_cpus;
	globals.thread_count = DEFAULT_THREAD_COUNT;
	globals.test_count = DEFAULT_TEST_COUNT;
	globals.filesize = DEFAULT_FILE_SIZE;
	globals.buf_size = DEFAULT_BUF_SIZE;
	globals.off0 = DEFAULT_OFF_0;

	globals.log_fd = -1;
	globals.base_dir_fd = -1;
	globals.testfile_dir_fd = -1;
	globals.log_dir_fd = -1;
	globals.cgroup_fd = -1;

	globals.verify_frequency = 0; // default to verify at end only
	globals.update_timer = (struct timeval){ .tv_sec = DEFAULT_UPDATE_DELAY_S, .tv_usec = DEFAULT_UPDATE_DELAY_US };


	uname(&globals.uts);

	setvbuf(stdout, NULL, _IONBF, 0); // make stdout unbuffered

	pthread_key_create(&globals.process_type_key, NULL);
	pthread_key_create(&globals.thread_id_key, NULL);
	pthread_key_create(&globals.proc_id_key, NULL);
	pthread_key_create(&globals.process_args_key, NULL);
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

		{ "verify",	required_argument, 0, 'V' },
		{ NULL, 0, 0, 0 },
	};
	int ret = EXIT_SUCCESS;

	do_global_init(argv[0]);

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "b:c:o:p:s:t:u:V:", long_options, &long_index)) != -1) {
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
			case 'V':
				globals.verify_frequency = strtoul(optarg, NULL, 10);
				break;

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

	if (globals.off0 > globals.buf_size) {
		global_output("initial offset (%lu) is greater than buffer size (%lu); reducing to a sane offset: %lu\n",
			globals.off0, globals.buf_size, globals.off0 % globals.buf_size);
		globals.off0 %= globals.buf_size;
	}

	if (globals.online_cpus < 2)
		global_output("***** WARNING ***** system only has one cpu; it is unclear whether this reproducer will work if the system does not have at least 2 cpus *****\n\nattempting to continue anyway\n\n");
	if (globals.proc_count < 2) {
//		return msg_usage(EXIT_FAILURE, "this reproducer will probably not work with fewer than 2 test processes\n");
		output("***** WARNING ***** this reproducer will probably not work with fewer than 2 test processes;\n\nuse '-p <process_count>' to specify more than 1 process\n\n");
		return 1;
	}

	if (globals.thread_count < 2)
		return msg_usage(EXIT_FAILURE, "this reproducer will probably not work with fewer than 2 thread per test process\n");
	if (globals.off0 + globals.buf_size > globals.filesize)
		return msg_usage(EXIT_FAILURE, "buffer size is larger than the filesize!\n");
	if (globals.off0 + globals.buf_size * globals.thread_count > globals.filesize)
		return msg_usage(EXIT_FAILURE, "total buffer size is larger than the filesize!\n");

	return ret;
}

int main(int argc, char *argv[]) {
	int ret = EXIT_FAILURE;

	if ((ret = parse_args(argc, argv)) != EXIT_SUCCESS)
		goto out;

	clock_gettime(CLOCK_REALTIME, &globals.start_time);

	ret = do_testing();

out:
	free_mem(globals.canonical_base_dir_path);

	return ret;
}
