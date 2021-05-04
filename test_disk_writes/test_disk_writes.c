/*
	Frank Sorenson <sorenson@redhat.com>, 2021

	test_disk_writes.c
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

#if HAVE_LIBNUMA
#include <numa.h>
#endif

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)
#define TiB (KiB * KiB * KiB * KiB)

#define DEFAULT_FILE_SIZE (1UL * TiB)
#define DEFAULT_BLOCK_SIZE (1ULL * MiB)
#define DEFAULT_FILE_COUNT 4
#define BUF_ALIGN (4096UL)

#define DEFAULT_PATH "."
#define FILE_TEMPLATE "testfile_%03d"

#define DEFAULT_TIMER_FREQ_S 30
#define DEFAULT_TIMER_FREQ_US 0

#define min(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a < b ? a : b; })
#define max(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a > b ? a : b; })
#define mb()	__asm__ __volatile__("mfence" ::: "memory")
#define nop()	__asm__ __volatile__ ("nop")

#define DEBUG 0

#define dprintf(args...) do { \
	if (DEBUG) { \
		printf(args); \
		fflush(stdout); \
	} \
} while (0)

typedef enum {
	run_state_unconf = 0,
	run_state_worker_ready,
	run_state_begin,
	run_state_exit
} __attribute__((packed)) run_state;

struct config_struct {
	uint64_t file_size;
	uint64_t block_size;
	int file_count;
	int stats_interval_sec;
	int stats_interval_usec;

	bool worker_delays;
	struct timespec sleep_time;
	bool use_direct;
	bool trunc_on_open;
	bool show_thread_cputime;
	bool show_thread_rusage;
	volatile run_state run_state;
	char *path;

	pid_t worker_thread_pid;
	clockid_t worker_thread_cpu_clockid;
	int exit;

#if HAVE_LIBNUMA
	struct bitmask *numa_cpu_nodes;
	struct bitmask *numa_mem_nodes;
	int numa_node_count;
	bool numa_available;
	bool set_numa_cpu;
	bool set_numa_mem;
#endif
} *config;

struct stats_struct {
	struct timespec start_time;
	struct timespec last_stat_time;
	uint64_t last_bytes_written;

	struct timespec last_worker_cputime;
	struct timespec final_worker_cputime;

	volatile int filenum;
	volatile uint64_t bytes_written;
	volatile struct rusage worker_rusage;
	volatile bool worker_rusage_valid;
} *stats;

#define NSEC (1000000000ULL)

#define PROGRESS_INTERVAL (50ULL * THOUSAND) /* don't flood */
#define likely(x)     __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

uint64_t entry_count;
int output_progress = 0;

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

void print_hmsns(uint64_t ns) {
	uint64_t h, m, s;

	s = ns / NSEC;
	ns %= NSEC;
	m = s / 60;
	s %= 60;
	h = m / 60;
	m %= 60;

	if (h)
		printf("%" PRIu64 ":%02" PRIu64 ":%02" PRIu64 ".%03" PRIu64, h, m, s, ns / 1000000);
	else if (m)
		printf("%" PRIu64 ":%02" PRIu64 ".%03" PRIu64, m, s, ns / 1000000);
	else
		printf("%" PRIu64 ".%03" PRIu64, s, ns / 1000000);
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

#if HAVE_LIBNUMA
int set_numa_cpu_nodes(const char *nodes_str) {
	if (numa_available() == -1) {
		printf("NUMA node cpu selection requested, but NUMA not available\n");
		exit(EXIT_FAILURE);
	}
	config->numa_available = true;
	config->numa_node_count = numa_num_configured_nodes();
//	config->numa_cpu_nodes = numa_allocate_nodemask();
//	numa_bitmask_clearall(config->numa_cpu_nodes);

	config->numa_cpu_nodes = numa_parse_nodestring(nodes_str);

	return 0;
}
int set_numa_mem_nodes(const char *nodes_str) {
	if (numa_available() == -1) {
		printf("NUMA node mem selection requested, but NUMA not available\n");
		exit(EXIT_FAILURE);
	}
	config->numa_available = true;
	config->numa_node_count = numa_num_configured_nodes();
	config->numa_mem_nodes = numa_parse_nodestring(nodes_str);

	return 0;
}
#endif

void print_rate(uint64_t size, struct timespec elapsed) {
//	uint64_t elapsed_ns = elapsed.tv_sec * NSEC + elapsed.tv_nsec;
	double elapsed_f = (double)elapsed.tv_sec +
		((double)elapsed.tv_nsec / (double)NSEC);
	double r;

	char *rate_str;

//	if (elapsed_ns > 0)
	if (elapsed_f != 0)
		r = (double)size / elapsed_f;
	else
		r = 0;

	rate_str = byte_units((uint64_t)r);

	printf("%s/sec", rate_str);
	free(rate_str);
}

void show_stats(int signum) {
	struct timespec now, current_worker_cputime, diff;
	uint64_t current_bytes_written;
	char *tmp;

	clock_gettime(CLOCK_REALTIME, &now);
	current_bytes_written = stats->bytes_written;
	if (config->show_thread_cputime && config->worker_thread_cpu_clockid) {
		if (config->run_state == run_state_begin) {
			if (clock_gettime(config->worker_thread_cpu_clockid, &current_worker_cputime) < 0)
				printf("error with clock_gettime(): %m\n");

			} else if (config->run_state == run_state_exit) {
				current_worker_cputime = stats->final_worker_cputime;
		}
	}

	if (config->show_thread_rusage) {
		stats->worker_rusage_valid = false;
		mb();
		kill(config->worker_thread_pid, SIGUSR1);
		while (!stats->worker_rusage_valid && (config->run_state != run_state_exit))
			nop();
	}

	printf("overall: ");

	diff = ts_diff(now, stats->start_time);
	print_hmsns((diff.tv_sec * NSEC) + diff.tv_nsec);
	tmp = byte_units(current_bytes_written);
	printf(" - %s @", tmp);
	free(tmp);

	print_rate(current_bytes_written, diff);

	if (stats->last_stat_time.tv_sec || stats->last_stat_time.tv_nsec) {
		uint64_t interval_bytes = current_bytes_written - stats->last_bytes_written;
		printf(";  interval: (");
		diff = ts_diff(now, stats->last_stat_time);
		print_hmsns((diff.tv_sec * NSEC) + diff.tv_nsec);
		tmp = byte_units(interval_bytes);
		printf(") %s @ ", tmp);
		free(tmp);

		print_rate(interval_bytes, diff);
	}
	stats->last_bytes_written = current_bytes_written;
	stats->last_stat_time = now;

	dprintf("; current file: %d", stats->filenum);
	printf("\n");

	if (config->show_thread_cputime && config->worker_thread_cpu_clockid) {
		printf("    worker cputime: ");
		print_hmsns((current_worker_cputime.tv_sec * NSEC) + current_worker_cputime.tv_nsec);

		printf("; interval: ");
		diff = ts_diff(current_worker_cputime, stats->last_worker_cputime);
		print_hmsns((diff.tv_sec * NSEC) + diff.tv_nsec);
		printf("\n");
		stats->last_worker_cputime = current_worker_cputime;
	}

/*
	struct rusage usage;
	if (getrusage(RUSAGE_CHILDREN, &usage) == -1) {
		printf("error calling getrusage(): %m\n");
	} else {
*/
	if (config->show_thread_rusage) {
			printf("  worker thread's stats:\n");
			printf("    user CPU time:   %6lu.%03lu\n", stats->worker_rusage.ru_utime.tv_sec, stats->worker_rusage.ru_utime.tv_usec/1000UL);
			printf("    system CPU time: %6lu.%03lu\n", stats->worker_rusage.ru_stime.tv_sec, stats->worker_rusage.ru_stime.tv_usec/1000UL);

			printf("    maximum resident set size (KiB): %ld\n", stats->worker_rusage.ru_maxrss);

			printf("    faults - major: %ld, minor: %ld\n", stats->worker_rusage.ru_majflt, stats->worker_rusage.ru_minflt);
			printf("    ctx switch - vol: %ld, invol: %ld\n", stats->worker_rusage.ru_nvcsw, stats->worker_rusage.ru_nivcsw);
			printf("    IO blocks - in: %ld, out: %ld\n", stats->worker_rusage.ru_inblock, stats->worker_rusage.ru_oublock);


		/* for some reason, this isn't entirely reliable... some numbers are sometimes zeroed */
		struct rusage usage;
		if (getrusage(RUSAGE_CHILDREN, &usage) == -1) {
		} else {
			printf("  monitor thread's view of worker thread's stats:\n");
			printf("    user CPU time:   %6lu.%03lu\n", usage.ru_utime.tv_sec, usage.ru_utime.tv_usec/1000UL);
			printf("    system CPU time: %6lu.%03lu\n", usage.ru_stime.tv_sec, usage.ru_stime.tv_usec/1000UL);

			printf("    maximum resident set size (KiB): %ld\n", usage.ru_maxrss);

			printf("    faults - major: %ld, minor: %ld\n", usage.ru_majflt, usage.ru_minflt);
			printf("    ctx switch - vol: %ld, invol: %ld\n", usage.ru_nvcsw, usage.ru_nivcsw);
			printf("    IO blocks - in: %ld, out: %ld\n", usage.ru_inblock, usage.ru_oublock);
		}
	}

}

void worker_get_rusage(int sig) {
	struct rusage usage;
/*
	if (getrusage(RUSAGE_SELF, &usage) == -1) {
*/
//	if (getrusage(RUSAGE_SELF, &stats->worker_rusage)) {
	if (getrusage(RUSAGE_SELF, &usage)) {
		printf("error calling getrusage(): %m\n");
	} else {
		stats->worker_rusage = usage;
/*
		printf("user CPU time:   %6lu.%03lu\n", usage.ru_utime.tv_sec, usage.ru_utime.tv_usec/1000UL);
		printf("system CPU time: %6lu.%03lu\n", usage.ru_stime.tv_sec, usage.ru_stime.tv_usec/1000UL);

		printf("maximum resident set size (KiB): %ld\n", usage.ru_maxrss);

		printf("faults - major: %ld, minor: %ld\n", usage.ru_majflt, usage.ru_minflt);
		printf("ctx switch - vol: %ld, invol: %ld\n", usage.ru_nvcsw, usage.ru_nivcsw);
		printf("IO blocks - in: %ld, out: %ld\n", usage.ru_inblock, usage.ru_oublock);
*/
	}
	stats->worker_rusage_valid = true;
	mb();
}

void worker_interrupt(int sig) {
	dprintf("worker got signal: %d\n", sig);

			/* CLOCK_PROCESS_CPUTIME_ID */
	if (
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stats->final_worker_cputime) < 0) {
/*			config->worker_thread_cpu_clockid, &stats->final_worker_cputime) < 0) { */
			printf("error in worker thread getting final cputime for worker thread: %m\n");
	}



	exit(0);
}

int writer_thread_work() {
	static int file_open_flags = O_CREAT|O_WRONLY;
	char filename[256];
	uint64_t remaining_bytes;
	int dfd, fd;
	char *buf;
	int ret;

	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &worker_interrupt;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (config->show_thread_rusage) {
		sa.sa_handler = &worker_get_rusage;
		sigaction(SIGUSR1, &sa, NULL);
	}

#if HAVE_LIBNUMA
	if (config->numa_cpu_nodes != NULL)
		ret = numa_run_on_node_mask(config->numa_cpu_nodes);
	if (config->numa_mem_nodes != NULL)
		numa_set_membind(config->numa_mem_nodes);
#endif

	posix_memalign((void **)&buf, BUF_ALIGN, config->block_size);
	memset(buf, 0x55, config->block_size);

	stats->bytes_written = 0;
	if ((dfd = open(config->path, O_RDONLY|O_DIRECTORY)) < 0) {
		printf("error opening working directory '%s': %m\n",
			config->path);
		return EXIT_FAILURE;
	}

	stats->filenum = 0;
	if (config->use_direct)
		file_open_flags |= O_DIRECT;
	if (config->trunc_on_open)
		file_open_flags |= O_TRUNC;

	/* tell the monitor thread we're ready, and wait for them to signal go */
	config->run_state = run_state_worker_ready;
	mb();
	while (config->run_state != run_state_begin)
		nop();

	while (42) {
		snprintf(filename, sizeof(filename) - 1, FILE_TEMPLATE, stats->filenum);
//		unlinkat(dfd, filename, 0);

		if ((fd = openat(dfd, filename, file_open_flags, 0644)) < 0) {
			printf("error opening file: %m\n");
			return EXIT_FAILURE;
		}
		if (!config->trunc_on_open)
			file_open_flags |= O_TRUNC; // only skip truncating the first file...

		remaining_bytes = config->file_size;
		while (remaining_bytes > 0) {
			size_t this_count = min(remaining_bytes, config->block_size);

			if ((ret = write(fd, buf, this_count)) != this_count)
				break;
			stats->bytes_written += this_count;
			remaining_bytes -= this_count;
			if (unlikely(config->worker_delays))
				nanosleep(&config->sleep_time, NULL);
		}
		close(fd);
		stats->filenum = (stats->filenum + 1) % config->file_count;
	}
	/* not that we'll ever get here */
	close(dfd);
	free(buf);

	return EXIT_SUCCESS;
}

int start_worker_thread() {
	pid_t cpid;
	int ret;

	if ((cpid = fork()) == 0) {
		return writer_thread_work();
	} else if (cpid < 0) {
		printf("error starting worker process: %m\n");
		exit(EXIT_FAILURE);
	}
	config->worker_thread_pid = cpid;

	if (config->show_thread_cputime) {
		if ((ret = clock_getcpuclockid(config->worker_thread_pid, &config->worker_thread_cpu_clockid)) != 0) {
			printf("Unable to get cpu clockid for worker thread: %s\n", strerror(ret));
			config->worker_thread_cpu_clockid = 0;
		}
	}

	return EXIT_SUCCESS;
}
void worker_handler(int sig) {
	config->run_state = run_state_exit;
	mb();
	dprintf("in worker handler\n");
}
void handle_interrupt(int sig) {
//	struct itimerval timer = { 0 };
	struct itimerval timer = { {0, 0}, {0, 0} };

	config->run_state = run_state_exit;
	mb();

	setitimer(ITIMER_REAL, &timer, NULL); // stop the timer
	dprintf("got interrupt...  killing worker and exiting\n");
	kill(config->worker_thread_pid, sig);
	waitpid(config->worker_thread_pid, NULL, 0);
	dprintf("returning from the monitor interrupt handler\n");
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

	/* wait for worker to say they're ready ... */
	while (config->run_state != run_state_worker_ready)
		nop();
	config->run_state = run_state_begin;
	mb();

	/* ... before getting the start time */
        clock_gettime(CLOCK_REALTIME, &stats->start_time);

	/* ... and starting the timer */
	sa.sa_handler = &show_stats;
	sigdelset(&signal_mask, SIGALRM);
	sigaction(SIGALRM, &sa, NULL);
	setitimer(ITIMER_REAL, &timer, 0);

	while (config->run_state != run_state_exit)
		sigsuspend(&signal_mask);\
	return EXIT_SUCCESS;
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
//printf("'%s' -> uint_size: %" PRIu64 "; long double size: %LF; have_uint: %d; shift: %d\n",
//	size_str, uint_size, size, have_uint, shift);
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


void usage(char *cmd, int ret) {
	printf("usage: %s [ ... options ... ]\n", cmd);
	printf("\t[-b | --block_size=<block_size>]\n");
	printf("\t[-c | --count=<file_count>]\n");
	printf("\t[-d | --direct]\n");
	printf("\t[-D | --delay=<seconds_between_writes>]\n");
	printf("\t[-i | --stats_interval=<seconds_between_updates>]\n");
	printf("\t[-n | --notrunc]\n");
	printf("\t[-p | --path=<test_directory>]\n");
	printf("\t[-s | --size=<file_size>]\n");
	printf("\t[-t | --thread_rusage]\n");
	printf("\t[-T | --thread_cputime]\n");
#if HAVE_LIBNUMA
	printf("\n");
	printf("\t[-N <numa_cpu_nodes> | --cpunodebind=<numa_cpu_nodes>]\n");
	printf("\t[-m <numa_mem_nodes> | --membind=<numa_mem_nodes>]");
#endif
	printf("\n");
	exit(ret);
}

static inline void set_defaults(void) {
	config->file_size = DEFAULT_FILE_SIZE;
	config->block_size = DEFAULT_BLOCK_SIZE;
	config->file_count = DEFAULT_FILE_COUNT;
	config->path = strdup(DEFAULT_PATH);
	config->stats_interval_sec = DEFAULT_TIMER_FREQ_S;
	config->stats_interval_usec = DEFAULT_TIMER_FREQ_US;

	config->worker_delays = false;
	config->sleep_time = (struct timespec){ 0, 0 };

	config->use_direct = false;
	config->trunc_on_open = true;
	config->show_thread_rusage = false;
	config->show_thread_cputime = false;
	config->run_state = run_state_unconf;
	stats->final_worker_cputime = (struct timespec){0, 0};

#if HAVE_LIBNUMA
	config->numa_cpu_nodes = NULL;
	config->numa_mem_nodes = NULL;
	config->numa_node_count = -1;
	config->numa_available = false;
	config->set_numa_cpu = false;
	config->set_numa_mem = false;
#define LIBNUMA_OPTS "m:N:"
#else
#define LIBNUMA_OPTS ""
#endif
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
		{ "thread_rusage", no_argument, 0, 't'},
		{ "thread_cputime", no_argument, 0, 'T'},
		{ "delay", required_argument, 0, 'D'},
		{ "notrunc", no_argument, 0, 'n'},
#if HAVE_LIBNUMA
		{ "cpunodebind", required_argument, 0, 'N' },
		{ "membind", required_argument, 0, 'm' },
#endif
		{ NULL, 0, 0, 0 }
	};
	int ret = EXIT_FAILURE;

	set_defaults();
	opterr = 0;
//	while ((opt = getopt_long(argc, argv, "s:b:c:di:m:N:p:",
	while ((opt = getopt_long(argc, argv, "s:b:c:dD:i:np:tT" LIBNUMA_OPTS,
		long_options, &long_index)) != -1) {
		switch (opt) {
			case 's':
				config->file_size = parse_size(optarg);
				break;
			case 'b':
				config->block_size = parse_size(optarg);
				break;
			case 'c': {
				if (optarg != NULL) {
					config->file_count = strtol(optarg, NULL, 10);
				} else {
					printf("broken 'c' argument\n");
				}
				break;
				}
			case 'd':
				config->use_direct = true;
				break;
			case 'D': {
					long double sleep_time = strtod(optarg, NULL);
					config->sleep_time.tv_sec = truncl(sleep_time);
					config->sleep_time.tv_nsec = truncl(sleep_time * 1000000000.0 -
						((long double)config->sleep_time.tv_sec * 1000000000.0));
					config->worker_delays = true;
				}
				break;
			case 'i': {
					double interval = strtod(optarg, NULL);
					config->stats_interval_sec = truncl(interval);
					config->stats_interval_usec =
						truncl(interval * 1000000.0 -
							((long double)config->stats_interval_sec * 1000000.0));
				}
				break;
			case 'n':
				config->trunc_on_open = false;
				break;
#if HAVE_LIBNUMA
			case 'm': {
					set_numa_mem_nodes(optarg);

				}
				break;
			case 'N': {
					set_numa_cpu_nodes(optarg);
				}
				break;
#endif
			case 'p':
				free(config->path);
				config->path = strdup(optarg);
				break;
			case 't':
				config->show_thread_rusage = true;
				break;
			case 'T':
				config->show_thread_cputime = true;
				break;
			case 'h':
				ret = EXIT_SUCCESS;
			default:
				printf("opt: %c\n", opt);
				usage(argv[0], ret);
				break;;
		}
	}
	if (config->file_size == 0 || config->block_size == 0 || config->file_count == 0 ||
		(config->stats_interval_sec == 0 && config->stats_interval_usec == 0))
		usage(argv[0], EXIT_FAILURE);

	printf("path: %s\n", config->path);
	printf("file size: %" PRIu64 "\n", config->file_size);
	printf("block size: %" PRIu64 "\n", config->block_size);
	printf("file count: %d\n", config->file_count);
	printf("seconds between stats updates: %d.%06d\n",
		config->stats_interval_sec, config->stats_interval_usec);
	printf("opening with O_DIRECT: %s\n", config->use_direct ? "true" : "false");

	return 0;
}

int main(int argc, char *argv[]) {
//	struct timespec now, diff;




	if ((config = mmap(NULL, sizeof(struct stats_struct),
		PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
		printf("an error occurred during mmap(): %m\n");
		return EXIT_FAILURE;
	}
//	memset(&config, 0, sizeof(config));
	memset(config, 0, sizeof(struct config_struct));

	if ((stats = mmap(NULL, sizeof(struct stats_struct),
		PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
		printf("an error occurred during mmap(): %m\n");
		return EXIT_FAILURE;
	}
//	memset(&stats, 0, sizeof(stats));
	memset(stats, 0, sizeof(struct stats_struct));

	parse_opts(argc, argv);

#if 0

#define test_parse_size(s_str) do { \
	uint64_t s_uint; \
	s_uint = parse_size(s_str); \
	if (s_uint > 0) \
		printf("'%s' is parsed as: %" PRIu64 "\n", \
			s_str, s_uint); \
	else \
		printf("'%s' could not be parsed\n", s_str); \
	printf("\n"); \
} while (0)

	test_parse_size("1024");
	test_parse_size("1K");
	test_parse_size("4K");
	test_parse_size("2.4MB");
	test_parse_size("8 G");
	test_parse_size("3 gA");
	test_parse_size("2    Meg");
	test_parse_size("2  MiB");
	test_parse_size("4.8 GiB");
	test_parse_size("0.8 GiB");
	test_parse_size("1.0 GiB");
#endif

	if (start_worker_thread() == EXIT_SUCCESS) {
		monitor_thread();
		show_stats(0);
	}

	return EXIT_SUCCESS;
}
