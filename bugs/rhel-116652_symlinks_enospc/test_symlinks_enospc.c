/*
	Frank Sorenson <sorenson@redhat.com> 2025

	program to test whether symlink creation initiates release of
	preallocated file space when receiving ENOSPC
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#define KiB (1024)
#define MiB (KiB * KiB)

#define FILE_SIZE (64 * KiB * 5)
#define BUFSIZE (64 * KiB)
#define FILE_MAX 10000

#define MAX_RETRY_COUNT 250
#define RETRY_DELAY 50000

int main(int argc, char *argv[]) {
	char *path = argv[1], *filename, *linkname;
	int dfd, fd, i, retry_count;
	long bytes_remaining, write_size;
	struct statvfs stvfs;
	char *buf;

	if (argc != 2) {
		printf("usage: %s <path>\n", argv[0]);
		return EXIT_FAILURE;
	}

	if ((dfd = open(path, O_RDONLY|O_DIRECTORY)) < 0) {
		printf("error opening directory '%s': %m\n", path);
		return EXIT_FAILURE;
	}

	asprintf(&filename, "file%06d", FILE_MAX - 1);
	asprintf(&linkname, "link%06d", FILE_MAX - 1);

	buf = malloc(BUFSIZE);
	memset(buf, 0xaa, BUFSIZE);

	fstatvfs(dfd, &stvfs);
	printf("filesystem - block size: %lu, total blocks: %lu, free blocks: %lu\n",
		stvfs.f_bsize, stvfs.f_blocks, stvfs.f_bfree);

	for (i = 0 ; i < FILE_MAX ; i++) {
		sprintf(filename, "file%06d", i);
		sprintf(linkname, "link%06d", i);

		if ((fd = openat(dfd, filename, O_CREAT|O_WRONLY|O_TRUNC, 0644)) < 0) {
			printf("error opening file '%s': %m\n", filename);
			return EXIT_FAILURE;
		}
		bytes_remaining = FILE_SIZE;
		while (bytes_remaining > 0) {
			if (bytes_remaining > BUFSIZE)
				write_size = BUFSIZE;
			else
				write_size = bytes_remaining;
			if ((write(fd, buf, write_size)) != write_size) {
				printf("error writing to '%s': %m\n", filename);
				return EXIT_FAILURE;
			}
			bytes_remaining -= write_size;
		}

		close(fd);
		fstatvfs(dfd, &stvfs);
		printf("created file '%s' free blocks: %ld\n", filename, stvfs.f_bfree);

		retry_count = 0;
		while ((symlinkat(filename, dfd, linkname)) < 0) {
			fstatvfs(dfd, &stvfs);

			printf("try %d - error creating symlink '%s': %m - free blocks: %ld\n",
				retry_count + 1, linkname, stvfs.f_bfree);

			if (retry_count >= MAX_RETRY_COUNT) {
				printf("unable to create symlink %d times\n", retry_count + 1);
				break;
			}

			retry_count++;
			usleep(RETRY_DELAY);
		}
		fstatvfs(dfd, &stvfs);
		printf("try %d - created symlink '%s' - free blocks on device: %ld\n",
			retry_count + 1, linkname, stvfs.f_bfree);
	}
	close(dfd);

	return EXIT_SUCCESS;
}
