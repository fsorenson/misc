/*
	Frank Sorenson <sorenson@redhat.com>, 2021

	drop_cached_file.c

		instruct the kernel to drop cached file pages for the given files

	# gcc drop_cached_file.c -o drop_cached_file -lm

	./drop_cached_file [ --sleep <sleep_time> | -s <sleep_time> ] [ -q | --quiet ] [ -d | --daemon ] <filename> [<filename> ... ]
	-s | --sleep <sleep_time>
		repeat the resynchronization, after sleeping for <sleep_time> seconds
	-q | --quiet
		suppress errors opening files
	-d | --daemon
		fork and sync the files in the background
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

static struct option long_options[] = {
	{ "daemon", no_argument, NULL, 'd' },
	{ "sleep", required_argument, NULL, 's' },
	{ "quiet", no_argument, NULL, 'q' },
	{ "help", no_argument, NULL, 'h' },
};

int usage(const char *cmd, int ret) {
	printf("usage: %s <options> <filename> [<filename> ... ]\n", cmd);

	printf("\n\toptions:\n");
	printf("\t-s | --sleep <sleep_time>\n");
	printf("\t\trepeat the resynchronization, after sleeping for <sleep_time> seconds\n");

	printf("\t-q | --quiet\n");
	printf("\t\tsuppress errors opening files\n");

	printf("\t-d | --daemon\n");
	printf("\t\tfork and sync the files in the background\n");

	return ret;
}

int main(int argc, char *argv[]) {
	int long_index = 0, opt = 0, fd, i;
	struct timespec sleep_time = { 0, 0 };
	bool repeat = false, quiet = false, daemon = false;

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "dhqs:", long_options, &long_index)) != -1) {
		switch (opt) {
			case 'd':
				daemon = true;
				break;
			case 'q':
				quiet = true;
				break;
			case 's': {
				char *endptr;
				long double tmp = strtod(optarg, &endptr);

				if (endptr == optarg) {
					printf("could not parse sleep time: %s\n", optarg);
					return usage(argv[0], EXIT_FAILURE);
				}

				sleep_time.tv_sec = truncl(tmp);
				sleep_time.tv_nsec = truncl(tmp * 1000000000.0 -
					((long double)sleep_time.tv_sec * 1000000000.0));
					repeat = true;
				}
				break;
			case 'h':
				return usage(argv[0], EXIT_SUCCESS);
				break;
			default:
				printf("unknown option\n");
				return usage(argv[0], EXIT_FAILURE);
				break;
		}
	}
	if (optind == argc) {
		printf("no files specified\n");
		return usage(argv[0], EXIT_SUCCESS);
	}

	if (daemon && !repeat) {
		printf("not repeating, so not daemonizing\n");
		daemon = false;
	}

	if (daemon) {
		pid_t cpid;

		if ((cpid = fork()) != 0) {
			printf("forked child process %d\n", cpid);
			return EXIT_SUCCESS;
		}
	}
	do {
		for (i = optind ; i < argc ; i++) {
			if ((fd = open(argv[i], O_RDONLY|O_DSYNC)) < 0) {
				if (!quiet)
					printf("could not open '%s': %m\n", argv[i]);
			} else {
				fsync(fd);

				// per manpage for posix_fadvise(2):
				// POSIX_FADV_DONTNEED attempts to free
				// cached pages associated with the specified region.
				posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
				close(fd);
			}
		}
		if (repeat)
			nanosleep(&sleep_time, NULL);
	} while (repeat);
	return EXIT_SUCCESS;
}
