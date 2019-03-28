/*
	Frank Sorenson - <sorenson@redhat.com> - 2019

	test program to open a file and enter a loop:
		read()
		sleep()

	# ./periodic_read <testfile> [<sleep_ms>]
	(default sleep_ms is 1000 ms - 1s)
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#define BUF_SIZE (16384)

#define msg_exit(ret, args...) do { \
	printf("%s@%s:%d: ", __func__, __FILE__, __LINE__); \
	printf(args); exit(ret); } while (0)

int main(int argc, char *argv[]) {
	struct timespec ts;
	char *filename;
	unsigned long sleep_ms = 1000;
	char *buf;
	int ret;
	int fd;

	if (argc == 3)
		sleep_ms = strtoul(argv[2], NULL, 10);
	else if (argc != 2)
		msg_exit(1, "Usage: %s <filename> [<sleep_ms>]\n\t(default is 1000 ms)\n", argv[0]);

	filename = argv[1];
	ts.tv_sec = sleep_ms / 1000UL;
	ts.tv_nsec = sleep_ms % 1000UL * 1000000UL;
	posix_memalign((void **)&buf, 4096, BUF_SIZE);

	if ((fd = open(filename, O_RDONLY|O_DIRECT)) < 0)
		msg_exit(EXIT_FAILURE, "Could not open '%s': %m\n", filename);

	while (42) {
		if ((ret = read(fd, buf, BUF_SIZE)) == -1)
			msg_exit(EXIT_FAILURE, "failed to read: %m\n");
		printf(".");
		fflush(stdout);
		nanosleep(&ts, NULL);
	}
	return EXIT_FAILURE; /* it's an infinite loop... it had better not break out */
}
