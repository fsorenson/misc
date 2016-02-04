/*
	Frank Sorenson <sorenson@redhat.com>, 2016

	test the rate at which getpwuid_r() calls complete for a particular user

	$ gcc test_getpwuid.c -o test_getpwuid -lrt

	$ ./test_getpwuid <uid|username> <count>

	for example, to make 1000 calls for uid 1001:
	$ ./test_getpwuid 1001 1000
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <ctype.h>
//#include <sys/stat.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <signal.h>

#define NSEC (1000000000UL)
#define USEC (1000000UL)
#define MSEC (1000UL)

struct test_info_struct {
	struct timespec start_time;
	struct timespec stop_time;
	uint64_t calls_requested;
	uint64_t counter;
} test_info;

struct timespec elapsed(const struct timespec start, const struct timespec stop) {
	struct timespec ret, a, b;

	if ((start.tv_sec > stop.tv_sec) ||
			((start.tv_sec == stop.tv_sec) && (start.tv_nsec > stop.tv_nsec))) {
		a = stop; b = start;
	} else {
		b = stop; a = start;
	}

	ret.tv_sec = b.tv_sec - a.tv_sec;
	ret.tv_nsec = b.tv_nsec - a.tv_nsec;
	if (ret.tv_nsec < 0) {
		ret.tv_nsec += NSEC;
		ret.tv_sec--;
	}

	return ret;
}

void output_results(void) {
        uint64_t calls_completed = test_info.calls_requested - test_info.counter - 1;

        if (calls_completed > 0) {
                struct timespec e = elapsed(test_info.start_time, test_info.stop_time);
                uint64_t s = e.tv_sec * NSEC + e.tv_nsec;
                uint64_t nsec = s / calls_completed;

                printf("calls requested: %" PRIu64 ", completed: %" PRIu64 "\n",
			test_info.calls_requested, calls_completed);
                printf("elapsed time: %ld.%09ld seconds\n", e.tv_sec, e.tv_nsec);
		printf("time/call: ");
		if (nsec > USEC)
			printf("%" PRIu64 ".%06" PRIu64 " msec/call (%" PRIu64 " nsec/call)\n",
				nsec / (NSEC / MSEC), nsec % (NSEC / MSEC),
				nsec);
		else if (nsec > MSEC)
			printf("%" PRIu64 ".%03" PRIu64 " usec/call (%" PRIu64 " nsec/call)\n",
				nsec / (NSEC / USEC), nsec % (NSEC / MSEC),
				nsec);
		else
			printf("%" PRIu64 " nsec/call\n", nsec);
        }
}

static void interrupted(int sig) {
        printf("Interrupted...  outputting statistics\n");
        clock_gettime(CLOCK_REALTIME, &test_info.stop_time);
        output_results();
        exit(EXIT_FAILURE);
}


int main(int argc, char *argv[]) {
	struct passwd pwd, *result;
	struct sigaction sa;
	char *username, *buf;
	size_t bufsize;
	uid_t uid;
	int ret;

	if (argc != 3) {
		printf("Usage: %s <uid|username> <count>\n", argv[0]);
		return EXIT_FAILURE;
	}

	if ((bufsize = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1)
		bufsize = 16384;	/* unknown, but this ought to be big enough */

	if ((buf = malloc(bufsize)) == NULL) {
		perror("malloc");
               return EXIT_FAILURE;
	}

	if (isdigit(argv[1][0]))
		uid = strtol(argv[1], NULL, 10);
	else {
		username = argv[1];
		if ((ret = getpwnam_r(argv[1], &pwd, buf, bufsize, &result)) != 0) {
			printf("An error occurred while calling getpwnam_r(%s): %m\n",
				argv[1]);
			return EXIT_FAILURE;
		} else if (result == NULL) {
			printf("Unable to look up user info for '%s'\n",
				argv[1]);
			return EXIT_FAILURE;
		}
		uid = pwd.pw_uid;
	}

	test_info.calls_requested = strtoull(argv[2], NULL, 10);
	test_info.counter = test_info.calls_requested;

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sa.sa_handler = &interrupted;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);

	clock_gettime(CLOCK_REALTIME, &test_info.start_time);
	while (test_info.counter-- > 0) {
		if (((ret = getpwuid_r(uid, &pwd, buf, bufsize, &result)) != 0) ||
				(result == NULL)) {
			clock_gettime(CLOCK_REALTIME, &test_info.stop_time);
			if (ret != 0)
				printf("An error occurred while calling getpwuid_r(%d): $m\n",
					uid);
			else
				printf("Unable to look up user info for uid %d\n",
					uid);
			output_results();
			return EXIT_FAILURE;
		}
	}
	clock_gettime(CLOCK_REALTIME, &test_info.stop_time);
	output_results();

	return EXIT_SUCCESS;
}
