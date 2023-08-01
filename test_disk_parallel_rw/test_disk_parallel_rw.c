/*
	Frank Sorenson <sorenson@redhat.com>, 2023

	Program to perform reads or writes in parallel to multiple files

	Also will start processes simply burning cpu or yielding immediately



*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <ctype.h>
#include <sched.h>

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)
#define TiB (KiB * KiB * KiB * KiB)
#define NSEC (1000000000ULL)

#define DEFAULT_FILE_SIZE (2UL * GiB)
#define DEFAULT_BLOCK_SIZE (128 * KiB)
#define DEFAULT_CHILD_COUNT 100
#define DEFAULT_BURN_COUNT 0
#define DEFAULT_YIELD_COUNT 0
#define BUF_ALIGN (4096UL)

#define DEFAULT_TIMER_FREQ_S 1
#define DEFAULT_TIMER_FREQ_US 0

#define DEFAULT_PATH "."
#define FILE_TEMPLATE "testfile_%03d"

#define min(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a < b ? a : b; })
#define max(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a > b ? a : b; })
#define mb()    __asm__ __volatile__("mfence" ::: "memory")
#define nop()   __asm__ __volatile__ ("nop")

#define likely(x)     __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)


typedef enum {
	unconfigured = 0,
	perform_reads = 1,
	perform_writes = 2,
} read_write_t;

struct config_struct {
	uint64_t file_size;
	uint64_t block_size;
	int child_count;
	int burn_count;
	int yield_count;
	int stats_interval_sec;
	int stats_interval_usec;
	read_write_t read_write;
	int dfd;

	bool worker_delays;
	struct timespec sleep_time;
	bool open_direct;
	bool open_sync;
	bool open_dsync;
	bool do_fdatasync;
	bool trunc_on_open;
	char *path;

	pid_t *workers;
	pid_t *burners;
	pid_t *yielders;
	clockid_t worker_thread_cpu_clockid;
	int exit;
} *config;

struct stats_struct {
	uint64_t total_bytes;
	uint64_t total_progress;
	int running_count;
	int running_burners;
	int running_yielders;
	struct timespec start_time;
	struct timespec stop_time;
} *stats;

struct thread_config_struct {
	int child_id;
	int fd;
	char *filename;
	char *buf;
} *thread_config;

void print_hmsns(uint64_t ns) {
	uint64_t h, m, s;

	s = ns / NSEC;
	ns %= NSEC;
	m = s / 60;
	s %= 60;
	h = m / 60;
	m %= 60;

	if (h)
		output("%" PRIu64 ":%02" PRIu64 ":%02" PRIu64 ".%03" PRIu64, h, m, s, ns / 1000000);
	else if (m)
		output("%" PRIu64 ":%02" PRIu64 ".%03" PRIu64, m, s, ns / 1000000);
	else
		output("%" PRIu64 ".%03" PRIu64, s, ns / 1000000);
}
struct timespec ts_diff(const struct timespec ts1, const struct timespec ts2) {
	struct timespec ret, a, b;

	if ((ts1.tv_sec > ts2.tv_sec) ||
		((ts1.tv_sec == ts2.tv_sec) && (ts1.tv_nsec >= ts2.tv_nsec))) {
		a = ts1; b = ts2;
	} else {
		a = ts2; b = ts1;
	}
	ret.tv_sec = a.tv_sec - b.tv_sec - 1;
	ret.tv_nsec = a.tv_nsec - b.tv_nsec + NSEC;
	while (ret.tv_nsec >= NSEC) {
		ret.tv_sec++;
		ret.tv_nsec -= NSEC;
	}
	return ret;
}

uint64_t l1024(uint64_t x) {
	uint64_t r = __builtin_clzll(x);
	if (x < 1024)
		return 0;
	if (r == (sizeof(x)*8ul))
		return 0;
	return ((sizeof(x)*8ul) - 1 - r) / 10;
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
					output("size too large: %s\n", p);
					return 0;
					break;
				case 'e': shift++;
				case 'p': shift++;
				case 't': shift++;
				case 'g': shift++;
				case 'm': shift++;
				case 'k':
					shift++;
					break;
				default:
					goto out;
					break;
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
	output("unrecognized size: '%s'\n", p);
	return 0;
}

void do_drop_caches(void) {
	int fd;
	if ((fd = open("/proc/sys/vm/drop_caches", O_RDWR)) < 0) {
		output("unable to drop caches: %m\n");
		exit(0);
	}
	write(fd, "3\n", 2);
	close(fd);
}

int usage(char *cmd, int ret) {
	output("usage: %s [ ... options ... ]\n", cmd);

	output("\t[-r | --read ]\n");
	output("\t[-w | --write ]\n");

	output("\t[-c | --child=<child_count>] - start this many read/write child threads (default: %d)\n", DEFAULT_CHILD_COUNT);
	output("\t[-b | --block_size=<block_size>]\n");

	output("\t\tfor writes:\n");

	output("\t\t[-s | --size=<file_size>] - specify the per-testfile size\n");
	output("\t\t[-S <total_file_size>] - specify the total size of all testfiles\n");

	output("\t\t[-f | --fdatasync] - perform fdatasync() after each write\n");
	output("\t[-d | --direct]\n");
	output("\t[ --sync=<sync|dsync>] - open the file with O_SYNC or O_DSYNC (may be specified more than once)\n");

	output("\t[-i | --stats_interval=<seconds_between_updates>]\n");
	output("\t[-B | --burn=<thread_count>] - start threads which do nothing but burn cpu cycles\n");
	output("\t[-y | --yield=<thread_count>] - start threads which do nothing but immediately call sched_yield()\n");
	output("\t[-p | --path=<test_directory>]\n");

	output("\n");
	return ret;
}

void set_defaults(void) {
	config->file_size = DEFAULT_FILE_SIZE;
	config->block_size = DEFAULT_BLOCK_SIZE;
	config->read_write = unconfigured;
	config->child_count = DEFAULT_CHILD_COUNT;
	config->burn_count = DEFAULT_BURN_COUNT;
	config->yield_count = DEFAULT_YIELD_COUNT;
	config->path = strdup(DEFAULT_PATH);
	config->stats_interval_sec = DEFAULT_TIMER_FREQ_S;
	config->stats_interval_usec = DEFAULT_TIMER_FREQ_US;

	config->open_direct = false;
	config->open_sync = false;
	config->open_dsync = false;
	config->do_fdatasync = false;
	config->trunc_on_open = true;
	stats->stop_time = (struct timespec){ 0, 0 };
}

int parse_opts(int argc, char *argv[]) {
	int opt = 0, long_index = 0;
	static struct option long_options[] = {
		{ "size", required_argument, 0, 's' },
		{ "block_size", required_argument, 0, 'b' },
		{ "count", required_argument, 0, 'c' },
		{ "direct", no_argument, 0, 'd' },
		{ "path", required_argument, 0, 'p' },
		{ "stats_interval", required_argument, 0, 'i' },
		{ "notrunc", no_argument, 0, 'n'},
		{ "read", no_argument, 0, 'r' },
		{ "write", no_argument, 0, 'w' },
		{ "sync", required_argument, NULL, 'Z' },
		{ "fdatasync", no_argument, 0, 'f' },

		{ "burn", required_argument, 0, 'B' },
		{ "yield", required_argument, 0, 'y' },

		{ NULL, 0, 0, 0 }
	};
	int ret = EXIT_FAILURE;
	uint64_t total_testfile_size = 0;

	set_defaults();

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "s:S:b:B:c:dD:fi:np:rwy:Z:", long_options, &long_index)) != -1) {
		switch (opt) {
			case 's': config->file_size = parse_size(optarg); break;
			case 'S': {
				total_testfile_size = parse_size(optarg);
			} ; break;
			case 'b': config->block_size = parse_size(optarg); break;
			case 'B': config->burn_count = strtol(optarg, NULL, 10); break;
			case 'y': config->yield_count = strtol(optarg, NULL, 10); break;
			case 'c': {
					if (optarg != NULL)
						config->child_count = strtol(optarg, NULL, 10);
					else
						output("broken 'c' argument\n");
				} ; break;
			case 'd': config->open_direct = true; break;
			case 'f': config->do_fdatasync = true; break;
			case 'i': {
				char str[7], *ptr;
				config->stats_interval_sec = strtol(optarg, &ptr, 10);
				if (*ptr == '.') {
					ptr++;
					strncpy(str, ptr, 7);
					str[6] = '\0';
					ptr = str + strlen(str);
					while (strlen(str) < 6)
						*(ptr++) = '0';
					config->stats_interval_usec = strtol(str, NULL, 10);
				} else
					config->stats_interval_usec = 0;
			} ; break;
			case 'n':
				config->trunc_on_open = false; break;
			case 'p':
				free(config->path);
				config->path = strdup(optarg);
				break;
			case 'r': config->read_write = perform_reads; break;
			case 'w': config->read_write = perform_writes; break;
			case 'Z': {
				if (!strcmp(optarg, "sync")) config->open_sync = true;
				else if (!strcmp(optarg, "dsync")) config->open_dsync = true;
				else {
					output("error: unrecognized sync option: %s\n", optarg);
					exit(1);
				}
			} ; break;
			case 'h':
				ret = EXIT_SUCCESS;
			default:
				output("opt: %c\n", opt);
				usage(argv[0], ret);
				exit(0);
				break;
		}
	}


//	if (config->file_size == 0 || config->block_size == 0 || config->child_count == 0)
//	if (config->file_size == 0 || config->block_size == 0 || config->child_count < 0)
//		return usage(argv[0], EXIT_FAILURE);
	if (config->burn_count < 0 || config->yield_count < 0)
		return usage(argv[0], EXIT_FAILURE);

	if (config->child_count + config->burn_count + config->yield_count == 0) {
		output("no threads selected\n");
		return usage(argv[0], EXIT_FAILURE);
	}

	if (config->child_count) {
		if (config->block_size == 0) {
			output("invalid block size\n");
			return usage(argv[0], EXIT_FAILURE);
		}
		if (config->read_write == unconfigured)
			config->read_write = perform_reads;
		output("path: %s\n", config->path);
		output("thread count: %d\n", config->child_count);
		output("block size: %" PRIu64 "\n", config->block_size);
		output("read/write: %s\n", config->read_write == perform_reads ? "READ" : "WRITE");

		if (config->read_write == perform_writes) {
			if (total_testfile_size)
				config->file_size = total_testfile_size / config->child_count;
			if (config->file_size == 0) {
				output("invalid file size\n");
				return usage(argv[0], EXIT_FAILURE);
			}
			output("file size: %" PRIu64 "\n", config->file_size);
		}
		output("O_DIRECT: %s\n", config->open_direct ? "yes" : "no");
	}
	if (config->burn_count)
		output("starting %d proces%s burning cpu\n", config->burn_count, config->burn_count == 1 ? "" : "es");
	if (config->yield_count)
		output("starting %d proces%s yielding cpu\n", config->yield_count, config->yield_count == 1 ? "" : "es");

	return EXIT_SUCCESS;
}

void worker_interrupt(int sig) {
//	output("worker %d got signal %d\n", thread_config->child_id, sig);

	exit(0);
}

int writer_thread_work(int child_id) {
	static int file_open_flags = O_CREAT|O_WRONLY|O_TRUNC;
	uint64_t remaining_bytes;
	int ret = EXIT_FAILURE;

	memset(thread_config->buf, 0x55, config->block_size);

	if (config->open_direct)
		file_open_flags |= O_DIRECT;
	if (config->open_sync)
		file_open_flags |= O_SYNC;
	if (config->open_dsync)
		file_open_flags |= O_DSYNC;

	if ((thread_config->fd = openat(config->dfd, thread_config->filename, file_open_flags, 0644)) < 0) {
		output("child %d: error opening '%s': %m\n", thread_config->child_id, thread_config->filename);
		goto out;
	}
	ftruncate(thread_config->fd, config->file_size);
	if ((fallocate(thread_config->fd, 0, 0, config->file_size)) < 0) {
		output("child %d: unable to allocate disk space: %m\n", thread_config->child_id);
		goto out;
	}

	__atomic_add_fetch(&stats->total_bytes, config->file_size, __ATOMIC_SEQ_CST);
	remaining_bytes = config->file_size;
	while (remaining_bytes > 0) {
		uint64_t this_count = min(remaining_bytes, config->block_size);

		if ((ret = write(thread_config->fd, thread_config->buf, this_count)) != this_count) {
			output("child %d: short write: %m\n", thread_config->child_id);
			goto out;
		}
		remaining_bytes -= this_count;
		if (config->do_fdatasync)
			fdatasync(thread_config->fd);
		__atomic_add_fetch(&stats->total_progress, this_count, __ATOMIC_SEQ_CST);
	}
	fsync(thread_config->fd);
	ret = EXIT_SUCCESS;
out:
	return ret;
}
int reader_thread_work(int child_id) {
	static int file_open_flags = O_RDONLY;
	int ret = EXIT_FAILURE;
	struct stat st;

	if (config->open_direct)
		file_open_flags |= O_DIRECT;
	if (config->open_sync)
		file_open_flags |= O_SYNC;
	if (config->open_dsync)
		file_open_flags |= O_DSYNC;

	if ((thread_config->fd = openat(config->dfd, thread_config->filename, file_open_flags, 0644)) < 0) {
		output("child %d: error opening '%s': %m\n", thread_config->child_id, thread_config->filename);
		goto out;
	}

	fstat(thread_config->fd, &st);
	__atomic_add_fetch(&stats->total_bytes, st.st_size, __ATOMIC_SEQ_CST);

	while (42) {
		uint64_t bytes_read;

		if ((bytes_read = read(thread_config->fd, thread_config->buf, config->block_size)) < 0) {
			output("child %d: error reading: %m\n", thread_config->child_id);
			goto out;
		} else if (bytes_read == 0)
			break;
		__atomic_add_fetch(&stats->total_progress, bytes_read, __ATOMIC_SEQ_CST);
	}
	ret = EXIT_SUCCESS;
out:
	return ret;
}
int worker_thread(int child_id) {
	struct sigaction sa;
	int ret;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &worker_interrupt;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	thread_config = malloc(sizeof(struct thread_config_struct));
	thread_config->child_id = child_id;

	asprintf(&thread_config->filename, FILE_TEMPLATE, thread_config->child_id);
	posix_memalign((void **)&thread_config->buf, BUF_ALIGN, (((config->block_size + 4095)/4096)*4096));

	if (config->read_write == perform_reads)
		ret = reader_thread_work(child_id);
	else
		ret = writer_thread_work(child_id);

	close(thread_config->fd);
	free(thread_config->buf);
	free(thread_config->filename);

	exit(ret);
}
void do_burn(void) {
	volatile unsigned long i = 0;
	while (42)
		i++;
}
void do_yield(void) {
	while (42)
		sched_yield();
}

int start_worker_threads() {
	int i;
	int cpid;

	stats->running_burners = 0;
	if (config->burn_count)
		config->burners = malloc(config->burn_count * sizeof(pid_t));
	for (i = 0 ; i < config->burn_count ; i++) {
		if ((cpid = fork()) == 0)
			do_burn();
		config->burners[i] = cpid;
		stats->running_burners++;
	}
	stats->running_yielders = 0;
	if (config->yield_count)
		config->yielders = malloc(config->yield_count * sizeof(pid_t));
	for (i = 0 ; i < config->yield_count ; i++) {
		if ((cpid = fork()) == 0)
			do_yield();
		config->yielders[i] = cpid;
		stats->running_yielders++;
	}

	if (config->read_write == perform_reads)
		do_drop_caches();

	stats->running_count = 0;
	config->workers = malloc(config->child_count * sizeof(pid_t));
	for (i = 0 ; i < config->child_count ; i++) {
		if ((cpid = fork()) == 0)
			worker_thread(i); // should never return
		config->workers[i] = cpid;
		stats->running_count++;
	}
	return EXIT_SUCCESS;
}
static void worker_handler(int sig) {
	pid_t cpid;
	int i;

	while ((cpid = wait4(-1, NULL, WNOHANG, NULL)) != -1) {
		if (cpid == 0)
			break;
		for (i = 0 ; i < config->child_count ; i++)
			if (cpid == config->workers[i]) {
				config->workers[i] = 0;
				goto found;
			}
		for (i = 0 ; i < config->burn_count ; i++)
			if (cpid == config->burners[i]) {
				config->burners[i] = 0;
				goto found;
			}
		for (i = 0 ; i < config->yield_count ; i++)
			if (cpid == config->yielders[i]) {
				config->yielders[i] = 0;
				goto found;
			}
found:
		(void)i;
	}

	stats->running_count = 0;
	stats->running_burners = 0;
	stats->running_yielders = 0;
	for (i = 0 ; i < config->child_count ; i++) {
		if (config->workers[i])
			stats->running_count++;
	}
	for (i = 0 ; i < config->burn_count ; i++)
		if (config->burners[i])
			stats->running_burners++;
	for (i = 0 ; i < config->yield_count ; i++)
		if (config->yielders[i])
			stats->running_yielders++;

}
void kill_burn_yield(int sig) {
	int i;
	for (i = 0 ; i < config->burn_count ; i++)
		if (config->burners[i])
			kill(config->burners[i], sig);
	for (i = 0 ; i < config->yield_count ; i++)
		if (config->yielders[i])
			kill(config->yielders[i], sig);
}
static void handle_interrupt(int sig) {
	int i;

	for (i = 0 ; i < config->child_count ; i++) {
		if (config->workers[i])
			kill(config->workers[i], sig);
	}
	kill_burn_yield(sig);
}

static void show_stats(int sig) {
	uint64_t total_bytes = __atomic_add_fetch(&stats->total_bytes, 0, __ATOMIC_SEQ_CST);
	uint64_t total_progress = __atomic_add_fetch(&stats->total_progress, 0, __ATOMIC_SEQ_CST);
	struct timespec ts_now, elapsed;
	double pct = 0.0, raw_rate = 0.0;
	char *rate;

	if (stats->stop_time.tv_sec)
		ts_now = stats->stop_time;
	else
		clock_gettime(CLOCK_REALTIME, &ts_now);
	elapsed = ts_diff(stats->start_time, ts_now);

	if (total_bytes > 0)
		pct = (double)total_progress / (double)total_bytes * 100.0;

	raw_rate = (double)total_progress / ((double)elapsed.tv_sec + ((double)elapsed.tv_nsec / (double)NSEC));
	rate = byte_units((uint64_t)raw_rate);

	print_hmsns((elapsed.tv_sec * NSEC) + elapsed.tv_nsec);
	output(" - %"PRIu64" / %"PRIu64" - %4.1f %% - %s/sec\r", total_progress, total_bytes, pct, rate);

	free(rate);
}

int monitor_thread() {
	sigset_t signal_mask;
	struct sigaction sa;
	struct itimerval timer;

	sigfillset(&signal_mask);

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &worker_handler;
	sigdelset(&signal_mask, SIGCHLD);
	sigaction(SIGCHLD, &sa, NULL);

	sa.sa_handler = &handle_interrupt;
	sigdelset(&signal_mask, SIGINT);
	sigdelset(&signal_mask, SIGTERM);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	timer.it_value.tv_sec = timer.it_interval.tv_sec = config->stats_interval_sec;
	timer.it_value.tv_usec = timer.it_interval.tv_usec = config->stats_interval_usec;

	sa.sa_handler = &show_stats;
	sigdelset(&signal_mask, SIGALRM);
	sigaction(SIGALRM, &sa, NULL);
	setitimer(ITIMER_REAL, &timer, 0);

	while (stats->running_count)
		sigsuspend(&signal_mask);

	clock_gettime(CLOCK_REALTIME, &stats->stop_time);

	kill_burn_yield(SIGINT);
	while (stats->running_burners + stats->running_yielders)
		sigsuspend(&signal_mask);

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
	int ret;

	if ((config = mmap(NULL, sizeof(struct config_struct),
		PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
		output("an error occurred during mmap(): %m\n");
		return EXIT_FAILURE;
	}
	memset(config, 0, sizeof(struct config_struct));
	if ((stats = mmap(NULL, sizeof(struct stats_struct),
		PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
		output("an error occurred during mmap(): %m\n");
		return EXIT_FAILURE;
	}
	memset(config, 0, sizeof(struct stats_struct));

	if ((ret = parse_opts(argc, argv)) != EXIT_SUCCESS)
		return ret;

	if ((config->dfd = openat(AT_FDCWD, config->path, O_DIRECTORY|O_RDONLY)) < 0) {
		output("error opening directory: %m\n");
		return EXIT_FAILURE;
	}
	stats->total_bytes = 0;
	stats->total_progress = 0;

	clock_gettime(CLOCK_REALTIME, &stats->start_time);
	if (start_worker_threads() == EXIT_SUCCESS) {
		monitor_thread();
	} else
		return EXIT_FAILURE;

	show_stats(0);
	output("\n\n");
	return EXIT_SUCCESS;
}
