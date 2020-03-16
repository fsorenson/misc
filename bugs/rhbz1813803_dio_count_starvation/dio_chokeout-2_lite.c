#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>

#define KiB (1024ULL)
#define BUF_ALIGN (1024UL)
#define IO_SIZE (64ULL * KiB)

pid_t gettid(void) {
	return syscall(SYS_gettid);
}

void open_close_child(const char *path) {
	int fd;

	while (42) {
		if ((fd = open(path, O_RDWR)) < 0) {
			printf("child pid %d could not open testfile '%s': %m\n", gettid(), path);
			exit(EXIT_FAILURE);
		}
		close(fd);
	}
}
void dio_child(const char *path) {
	char *buf;
	int fd;

	if ((fd = open(path, O_RDONLY|O_DIRECT)) < 0) {
		printf("child pid %d could not open testfile '%s': %m\n", gettid(), path);
		exit(EXIT_FAILURE);
	}
	buf = malloc(IO_SIZE);
	while (42) {
		pread(fd, buf, IO_SIZE, 0);
	}
}

int main(int argc, char *argv[]) {
	int dio_kids, oc_kids;
	int total_children;
	char *path = NULL;
	pid_t cpid;
	int i;

	if (argc != 4) {
		printf("usage: %s <test_file> <dio_threads> <open_close_threads>\n", argv[0]);
		return EXIT_FAILURE;
	}

	path = strdup(argv[1]);
	dio_kids = strtol(argv[2], NULL, 10);
	oc_kids = strtol(argv[3], NULL, 10);

	if (dio_kids < 1) {
		printf("dio child count must be at least %d\n", 1);
		goto out;
	}

	if (oc_kids < 1) {
		printf("open/close child count must be at least %d\n", 1);
		goto out;
	}

	total_children = dio_kids + oc_kids;

	for (i = 0 ; i < total_children - 1; i++) {
		if ((cpid = fork()) == 0) {
			if (i < dio_kids)
				dio_child(path);
			else
				open_close_child(path);
		}
	}
	open_close_child(path);

out:
	return EXIT_FAILURE;
}
