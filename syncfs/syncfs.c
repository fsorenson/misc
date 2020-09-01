/*
	Frank Sorenson <sorenson@redhat.com>, 2020

	$ gcc -Wall syncfs.c -o syncfs
	$ ./syncfs / /mnt
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int syncfs(int fd) {
	return syscall(SYS_syncfs, fd);
}
int main(int argc, char *argv[]) {
	int fd, i;

	if (argc < 2) {
		printf("usage: %s <path> [<path> ... ]\n", argv[0]);
		return EXIT_FAILURE;
	}
	for (i = 1 ; i < argc ; i++) {
		if ((fd = open(argv[i], O_RDONLY)) < 0) {
			printf("failed to open '%s': %m\n", argv[i]);
			continue;
		}
		if (syncfs(fd) < 0)
			printf("syncfs('%s') failed: %m\n", argv[i]);
		close(fd);
	}

	return EXIT_SUCCESS;
}
