/*
	Frank Sorenson <sorenson@redhat.com>, 2021

	drop_cached_file.c

		instruct the kernel to drop cached file pages for the given files

	# gcc drop_cached_file.c -o drop_cached_file

	./drop_cached_file [-n | --noclose] [ --sleep <sleep_time> | -s <sleep_time> ] [ -q | --quiet ] [ -d | --daemon ] <filename> [<filename> ... ]
	-n | --noclose
		do not close file(s) between iterations
	-s | --sleep <sleep_time>
		repeat the resynchronization, after sleeping for <sleep_time> seconds
	-q | --quiet
		suppress errors opening files
	-d | --daemon
		fork and sync the files in the background
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>

static struct option long_options[] = {
	{ "daemon", no_argument, NULL, 'd' },
	{ "sleep", required_argument, NULL, 's' },
	{ "quiet", no_argument, NULL, 'q' },
	{ "noclose", no_argument, NULL, 'n' },
	{ "help", no_argument, NULL, 'h' },
};

int usage(const char *cmd, int ret) {
	printf("usage: %s <options> <filename> [<filename> ... ]\n", cmd);

	printf("\n\toptions:\n");
	printf("\t-n | --noclose\n");
	printf("\t\tdo not close file(s) between iterations\n");
	printf("\t-s | --sleep <sleep_time>\n");
	printf("\t\trepeat the resynchronization, after sleeping for <sleep_time> seconds\n");

	printf("\t-q | --quiet\n");
	printf("\t\tsuppress errors opening files\n");

	printf("\t-d | --daemon\n");
	printf("\t\tfork and sync the files in the background\n");

	return ret;
}

int main(int argc, char *argv[]) {
	int long_index = 0, opt = 0, i;
	struct timespec sleep_time = { 0, 0 };
	bool repeat = false, quiet = false, daemon = false, close_files = true;
	int *fds;

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "dhnqs:", long_options, &long_index)) != -1) {
		switch (opt) {
			case 'd':
				daemon = true;
				break;
			case 'n':
				close_files = false;
				break;
			case 'q':
				quiet = true;
				break;
			case 's': {
				char *end_ptr;

				sleep_time.tv_sec = strtoll(optarg, &end_ptr, 10);
				if (sleep_time.tv_sec == LLONG_MIN || sleep_time.tv_sec == LLONG_MAX) {
					if (errno == ERANGE)
						printf("could not convert '%s' to seconds\n", optarg);
					else
						printf("unknown parsing error: %m\n");
					return EXIT_FAILURE;
				}
				if (*end_ptr == '.') {
					uint64_t mult = 100000000;

					end_ptr++;
					while (isdigit(*end_ptr)) {
						sleep_time.tv_nsec += mult * (*end_ptr - '0');
						mult /= 10;
						end_ptr++;

						if (!mult)
							break;
					}
				}
				repeat = true;
			} ; break;
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
	fds = malloc((argc - optind + 1) * sizeof(int));
	for (i = 0 ; i < (argc - optind + 1) ; i++)
		fds[i] = -1;
	do {
		for (i = optind ; i < argc ; i++) {
			int fd_num = i - optind;
			if (close_files || fds[fd_num] == -1) {
				if ((fds[fd_num] = open(argv[i], O_RDONLY|O_DSYNC)) < 0) {
					if (!quiet)
						printf("could not open '%s': %m\n", argv[i]);
				}
			}

			if (fds[fd_num] >= 0) {
				fsync(fds[fd_num]);

				// per manpage for posix_fadvise(2):
				// POSIX_FADV_DONTNEED attempts to free
				// cached pages associated with the specified region.
				posix_fadvise(fds[fd_num], 0, 0, POSIX_FADV_DONTNEED);
			}
			if (close_files && fds[fd_num] >= 0) {
				close(fds[fd_num]);
				fds[fd_num] = -1;
			}
		}
		if (repeat)
			nanosleep(&sleep_time, NULL);
	} while (repeat);
	return EXIT_SUCCESS;
}
