/*
	Frank Sorenson <sorenson@redhat.com>, 2018

	call stat() on non-existent files, creating negative dentries
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>

#define DOES_NOT_EXIST  "_DoesNOTExist_"
#define FILENAME_PATTERN DOES_NOT_EXIST ".%.09" PRIu64

#define THOUSAND (1000ULL)
#define MILLION (THOUSAND * THOUSAND)

#define NSEC (1000000000ULL)

#define PROGRESS_INTERVAL (50ULL * THOUSAND) /* don't flood */
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
		ret.tv_sec ++;
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

void show_times(uint64_t count, uint64_t total, const struct timespec start_time) {
	struct timespec current_time;

	struct timespec elapsed;
	uint64_t elapsed_ns, estimated_total_ns, remaining_ns;
	long double pct;

	clock_gettime(CLOCK_REALTIME, &current_time);
	elapsed = ts_diff(start_time, current_time);

	elapsed_ns = elapsed.tv_sec * NSEC + elapsed.tv_nsec;

	if (!total) {
		printf("ERR\r");
		return;
	}
	pct = ((long double)count * 100.0) / (long double)total;
	estimated_total_ns = (uint64_t)(((long double)elapsed_ns * (long double)total) / (long double)count);
	if (estimated_total_ns < elapsed_ns)
		estimated_total_ns = elapsed_ns;

	remaining_ns = estimated_total_ns - elapsed_ns;

	printf("%'" PRIu64 " - %3.02LF%%   ", count, pct);

	print_hmsns(elapsed_ns);
	printf(" elapsed,  ");
	print_hmsns(remaining_ns);
	printf(" remaining,  ");
	print_hmsns(estimated_total_ns);

	printf(" total                 \r");
}

#define progress_counter(_ctr, _total, _start_time) do { \
	if (unlikely(output_progress)) { \
		if (unlikely(_ctr % PROGRESS_INTERVAL == 0)) { \
			show_times(_ctr, _total, _start_time); \
			fflush(stdout); \
		} \
	} \
} while (0)

int main(int argc, char *argv[]) {
	struct timespec start_time;
	uint64_t counter;
	struct stat st;
	char *fname;
	char *path;
	int dfd;

	if (argc != 3) {
		printf("Usage: %s <test_directory> <entry_count>\n", argv[0]);
		return EXIT_FAILURE;
	}
	path = argv[1];
	entry_count = strtoull(argv[2], NULL, 10);

	if (isatty(fileno(stdout)))
		output_progress = 1;

	if ((dfd = open(path, O_RDONLY|O_DIRECTORY)) < 0) {
		printf("Could not open directory '%s': %m\n", path);
		return EXIT_FAILURE;
	}
	asprintf(&fname, FILENAME_PATTERN, entry_count);

	clock_gettime(CLOCK_REALTIME, &start_time);
	for (counter = 0 ; counter < entry_count ; counter++) {
		progress_counter(counter, entry_count, start_time);
		sprintf(fname, FILENAME_PATTERN, counter);
		fstatat(dfd, fname, &st, 0); /* don't bother checking; expected to fail */
	}
	progress_counter(counter, entry_count, start_time);
	if (output_progress)
		printf("\n");
	free(fname);

	return EXIT_SUCCESS;
}
