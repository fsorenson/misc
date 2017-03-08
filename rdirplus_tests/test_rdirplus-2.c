/*
	Frank Sorenson, <sorenson@redhat.com>  2016

	Program to test READDIR/READDIRPLUS speed in a
	directory on an nfs mount with a large number of directory
	entries.

	uses getdents64() and stat() to simulate the calls that
	'ls' would make.

	intended to be started multiple times concurrently against
	the same directory over nfs


	# gcc -Wall test_rdirplus-2.c -o test_rdirplus-2 -l rt
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <sys/resource.h>
#include <signal.h>

#define KiB (1024ULL)

#define BUF_SIZE	(32ULL * KiB)

struct stats {
	struct timespec test_begin_time;
	struct timespec test_end_time;
	struct timespec now;

	struct timespec getdents_time;
	struct timespec stat_time;

	unsigned long buf_count;
	unsigned long dirent_count;

	struct rusage usage;
} stats;

struct linux_dirent64 {
	ino64_t		d_ino;
	off64_t		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[];
};

#define exit_fail(args...) do { \
	printf("Error %d: %s - ", errno, strerror(errno)); \
	printf(args); exit(EXIT_FAILURE); } while (0)

void hexprint(char *bytes, int len) {
	int i;
	int c;

	for (i = 0 ; i < len ; i ++) {
		c = bytes[i] & 0xFF;
		printf("'%c' %02x    ",
			isprint(c) ? c : '.',
			(unsigned int)c);
	}
	printf("\n");
}

struct timespec ts_elapsed(const struct timespec ts1, const struct timespec ts2) {
	struct timespec ret;

	ret.tv_sec = ts2.tv_sec - ts1.tv_sec - 1;
	ret.tv_nsec = ts2.tv_nsec - ts1.tv_nsec + 1000000000;

	while (ret.tv_nsec >= 1000000000) {
		ret.tv_sec ++;
		ret.tv_nsec -= 1000000000;
	}
	return ret;
}

struct timespec add_ts(const struct timespec ts1, struct timespec ts2) {
	struct timespec ret;

	ret.tv_sec = ts1.tv_sec + ts2.tv_sec;
	ret.tv_nsec = ts1.tv_nsec + ts2.tv_nsec;

	while (ret.tv_nsec >= 1000000000) {
		ret.tv_sec ++;
		ret.tv_nsec -= 1000000000;
	}
	return ret;
}

struct timespec add_elapsed(struct timespec tot, const struct timespec ts1, const struct timespec ts2) {
	struct timespec diff;
	struct timespec ret;

	diff = ts_elapsed(ts1, ts2);
	ret = add_ts(tot, diff);

	return ret;
}

long double tsdouble(struct timespec tv) {
	return (long double)tv.tv_sec + ((long double)tv.tv_nsec) / 1000000000.0;
}
long double tvdouble(struct timeval tv) {
	return (long double)tv.tv_sec + ((long double)tv.tv_usec) / 1000000.0;
}
static inline void start_timestamp(void) {
	clock_gettime(CLOCK_REALTIME, &stats.test_begin_time);
}
static inline void end_timestamp(void) {
	clock_gettime(CLOCK_REALTIME, &stats.test_end_time);
	if (getrusage(RUSAGE_THREAD, &stats.usage) == -1)
		exit_fail("reading resource usage");
}

void show_run_stats(void) {
	struct timespec test_runtime = { 0, 0 };

	test_runtime = ts_elapsed(stats.test_begin_time, stats.test_end_time);

	// don't forget we had to make an extra getdents call to get the 0 stop condition
	printf("\n%12s %8s %13s    %9s", "", "calls", "avg (ms)", "time (s)\n");
	printf("%12s %8lu %10.03Lf ms %6lu.%03lu s\n",
		"getdents", stats.buf_count + 1,
			(((long double)stats.getdents_time.tv_sec)*1000.0 + ((long double)stats.getdents_time.tv_nsec)/1000000.0) /
				((long double)stats.buf_count + 1.0),
			stats.getdents_time.tv_sec, stats.getdents_time.tv_nsec/1000000UL);
	printf("%12s %8lu %10.03Lf ms %6lu.%03lu s\n",
		"stat", stats.dirent_count,
			(((long double)stats.stat_time.tv_sec)*1000.0 + ((long double)stats.stat_time.tv_nsec)/1000000.0) /
				((long double)stats.dirent_count),
			stats.stat_time.tv_sec, stats.stat_time.tv_nsec/1000000UL);
	printf("%12s %8s %10s%3s %6lu.%03lu s\n",
		"total time", "", "", "", test_runtime.tv_sec, test_runtime.tv_nsec/1000000UL);


	printf("user CPU time:   %6lu.%03lu\n", stats.usage.ru_utime.tv_sec, stats.usage.ru_utime.tv_usec/1000UL);
	printf("system CPU time: %6lu.%03lu\n", stats.usage.ru_stime.tv_sec, stats.usage.ru_stime.tv_usec/1000UL);

#if 0
	long double call_time = tsdouble(stats.getdents_time) + tsdouble(stats.stat_time);
	long double runtime = tsdouble(test_runtime);
	long double pct1 = call_time / runtime * 100.0;
	printf("cpu %%: %6.02Lf\n", pct1);

	long double rustime = tvdouble(stats.usage.ru_utime) + tvdouble(stats.usage.ru_stime);
	long double pctcpu = rustime / runtime * 100.0;
	printf("pctcpu: %6.02Lf\n", pctcpu);
#endif
	printf("maximum resident set size (KiB): %ld\n", stats.usage.ru_maxrss);

	printf("faults - major: %ld, minor: %ld\n", stats.usage.ru_majflt, stats.usage.ru_minflt);
	printf("ctx switch - vol: %ld, invol: %ld\n", stats.usage.ru_nvcsw, stats.usage.ru_nivcsw);
	printf("IO blocks - in: %ld, out: %ld\n", stats.usage.ru_inblock, stats.usage.ru_oublock);
}

void interrupted(int sig) {
	struct timespec temp_tv;

	end_timestamp();
	temp_tv = ts_elapsed(stats.test_begin_time, stats.now);
	printf("%10lu.%03lu  %6lu.%03lu: test interrupted\n",
		stats.now.tv_sec, stats.now.tv_nsec / 1000000UL,
		temp_tv.tv_sec, temp_tv.tv_nsec / 1000000);

	show_run_stats();
	exit(EXIT_FAILURE);
}

void setup_sigs(void) {
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sa.sa_handler = interrupted;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
}

int do_test(char *directory) {
	struct linux_dirent64 *temp_de;
	struct timespec start_time;
	struct timespec interval_ts, overall_elapsed;
	unsigned long last_dirent_count;
	struct stat st;
	char filename[4096];
	char buf[BUF_SIZE];
	char *bpos;
	int nread;
	int dir_fd;

	start_timestamp();

	setup_sigs();

	if ((dir_fd = open(directory, O_RDONLY | O_DIRECTORY)) == -1)
		exit_fail("open call failed");

	for ( ; ; ) {
		clock_gettime(CLOCK_REALTIME, &start_time);
		nread = syscall(SYS_getdents64, dir_fd, buf, BUF_SIZE);
		clock_gettime(CLOCK_REALTIME, &stats.now);

		interval_ts = ts_elapsed(start_time, stats.now);
		stats.getdents_time = add_ts(stats.getdents_time, interval_ts);
		overall_elapsed = ts_elapsed(stats.test_begin_time, stats.now);

		stats.buf_count++;

		printf("%10lu.%03lu  %6lu.%03lu: getdents64() call %lu: %6lu.%06lu s\n",
			stats.now.tv_sec, stats.now.tv_nsec / 1000000UL,
			overall_elapsed.tv_sec, overall_elapsed.tv_nsec / 1000000UL,
			stats.buf_count,
			interval_ts.tv_sec, interval_ts.tv_nsec / 1000UL);

		if (nread == -1)
			exit_fail("getdents call failed");

		if (nread == 0)
			break;

		bpos = buf;
		last_dirent_count = stats.dirent_count;
		start_time = stats.now;
		while (bpos < buf + nread) {
			stats.dirent_count ++;
			if (stats.dirent_count < 2)
				continue; // no need to stat "." or ".."

			temp_de = (struct linux_dirent64 *)bpos;
			sprintf(filename, "%s", temp_de->d_name);

			fstatat(dir_fd, filename, &st, 0);
			bpos += temp_de->d_reclen;
		}
		clock_gettime(CLOCK_REALTIME, &stats.now);

		interval_ts = ts_elapsed(start_time, stats.now);
		stats.stat_time = add_ts(stats.stat_time, interval_ts);

		overall_elapsed = ts_elapsed(stats.test_begin_time, stats.now);
		printf("%10lu.%03lu  %6lu.%03lu: %lu stat() calls in: %6lu.%06lu s\n",
			stats.now.tv_sec, stats.now.tv_nsec / 1000000UL,
			overall_elapsed.tv_sec, overall_elapsed.tv_nsec / 1000000UL,
			stats.dirent_count - last_dirent_count, interval_ts.tv_sec, interval_ts.tv_nsec / 1000UL);
	}
	close(dir_fd);

	end_timestamp();

	return 0;
}

int main(int argc, char *argv[]) {
	char *directory;

	directory = argc > 1 ? argv[1] : ".";

	do_test(directory);
	show_run_stats();

	return EXIT_SUCCESS;
}
