#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#define SLEEP_TIME (5)

void print_usage(char *exe) {
	printf("usage: %s [ -w ] <lockfile>\n", exe);
	printf("\t-w - wait for the file lock\n");
}

int main(int argc, char *argv[]) {
	struct flock fl = {
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
		.l_type = F_WRLCK
	};
	bool lock_wait = false, have_lock = false;
	int ret = EXIT_FAILURE;
	int fd = -1, opt, lock_cmd;
	char *path;

	opterr = 0;
	while ((opt = getopt(argc, argv, "w")) != -1) {
		switch (opt) {
			case 'w':
				lock_wait = true;
				break;
			default:
				print_usage(argv[0]);
				goto out;
		}
	}
	path = argv[optind];

	if (path == NULL) {
		print_usage(argv[0]);
		goto out;
	}

	if ((fd = open(path, O_RDWR)) < 0) {
		printf("error opening file: %m\n");
		goto out;
	}

	do {
		if ((fcntl(fd, F_SETLK, &fl)) < 0) {
			if (!lock_wait) {
				printf("failed to get lock\n");
				goto out;
			}
			printf("Waiting for the file lock.\n");

			sleep(SLEEP_TIME);
		} else
			have_lock = true;
	} while (! have_lock);

	if (have_lock) {
		printf("File lock acquired.\n");
		printf("start a second copy of this program with the same parameters on another server.\n");
		printf("Press Enter or terminate this process to release the lock\n");
		getchar();
	}

out:
	if (have_lock) {
		fl.l_type = F_UNLCK;
		if ((fcntl(fd, F_SETLK, &fl)) < 0)
			printf("error unlocking file: %m\n");
		else
			ret = EXIT_SUCCESS;
	}
	if (fd >= 0) {
		if ((close(fd)) < 0)
			printf("error closing file: %m\n");
	}

	return ret;
}
