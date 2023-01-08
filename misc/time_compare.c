#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

#define ITER 10000000000ULL

#define NSEC (1000000000ULL)

void do_gtod(void) {
	struct timespec start, stop, diff;
	uint64_t counter = ITER;
	struct timeval tv;

	clock_gettime(CLOCK_REALTIME, &start);
	while (counter-- > 0)
		gettimeofday(&tv, NULL);
	clock_gettime(CLOCK_REALTIME, &stop);

	diff.tv_sec = stop.tv_sec - start.tv_sec;
	diff.tv_nsec = stop.tv_nsec - start.tv_nsec;
	while (diff.tv_nsec < 0) {
		diff.tv_nsec += NSEC;
		diff.tv_sec--;
	}
	printf("gettimeofday: %lu.%09lu\n", diff.tv_sec, diff.tv_nsec);
}
void do_clock_gettime(void) {
	struct timespec start, stop, diff;
	uint64_t counter = ITER;
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &start);
	while (counter-- > 0)
		clock_gettime(CLOCK_REALTIME, &ts);
	clock_gettime(CLOCK_REALTIME, &stop);

	diff.tv_sec = stop.tv_sec - start.tv_sec;
	diff.tv_nsec = stop.tv_nsec - start.tv_nsec;
	while (diff.tv_nsec < 0) {
		diff.tv_nsec += NSEC;
		diff.tv_sec--;
	}
	printf("clock_gettime: %lu.%09lu\n", diff.tv_sec, diff.tv_nsec);
}

int main(int argc, char *argv[]) {
	do_gtod();
	do_clock_gettime();

	return EXIT_SUCCESS;
}

