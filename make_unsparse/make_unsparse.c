/*
	Frank Sorenson <sorenson@redhat.com>, 2020

	make_sparse - program to un-sparse a file in-place

	Finds the 'holes' in a sparse file, and write zeros to the
	file in their place

	essentially the exact opposite of what fallocate does with:
	$ fallocate --dig-holes --keep-size <filename>

	$ gcc make_unsparse.c -o make_unsparse
	$ ./make_unsparse <file_to_make_unsparse>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define BUF_SIZE (1 * MiB)

#define VERBOSE 0

/*
2870169 23:37:07.810896 lseek(3</usr/lib64/libc-2.28.so>, 864, SEEK_SET) = 864 <0.000006>
2870169 23:37:07.813820 lseek(3</var/tmp/testfile>, 0, SEEK_SET) = 0 <0.000006>
2870169 23:37:07.813846 lseek(3</var/tmp/testfile>, 0, SEEK_DATA) = 0 <0.000007>
2870169 23:37:07.813872 lseek(3</var/tmp/testfile>, 0, SEEK_HOLE) = 2149580800 <0.000019>
2870169 23:37:24.867433 lseek(3</var/tmp/testfile>, 2149580800, SEEK_DATA) = -1 ENXIO (No such device or address) <0.000005>
*/

int usage(int argc, char *argv[], int ret) {
	printf("usage: %s <file_to_make_unsparse>\n", argv[0]);
	return ret;
}

int main(int argc, char *argv[]) {
	int fd;
	uint64_t holes_chewed = 0;
	uint64_t current_pos = 0;
	uint64_t file_size;
	uint64_t new_pos;
	struct stat st;
	size_t len;
	char *buf;

	if (argc != 2)
		return usage(argc, argv, EXIT_FAILURE);

	if ((stat(argv[1], &st)) < 0) {
		printf("Unable to locate '%s': %m\n", argv[1]);
		return EXIT_FAILURE;
	}

	if ((fd = open(argv[1], O_RDWR)) < 0) {
		printf("error opening file: %m\n");
		return EXIT_FAILURE;
	}

	buf = malloc(BUF_SIZE);
	memset(buf, 0, BUF_SIZE);

	file_size = lseek(fd, 0, SEEK_END);
	current_pos = lseek(fd, 0, SEEK_SET);
	while (42) {
		if (current_pos == file_size)
			break;
		if ((new_pos = lseek(fd, current_pos, SEEK_HOLE)) == (off_t)(-1)) {
			if (errno != ENXIO)
				printf("lseek(%d, %lu, SEEK_HOLE) failed with %m\n",
					fd, current_pos);
			break;
		}
		len = new_pos - current_pos;
#if VERBOSE
		printf("data from %lu to %lu (%lu bytes)\n", current_pos, new_pos, len);
#endif
		current_pos = new_pos;

		if ((new_pos = lseek(fd, current_pos, SEEK_DATA)) == (off_t)(-1)) {
			if (errno == ENXIO && current_pos < file_size) { /* file ends with a hole */
				new_pos = file_size;
			} else {
				if (errno != ENXIO)
					printf("lseek(%d, %lu, SEEK_DATA) failed with %m\n",
						fd, current_pos);
				break;
			}
		}

		len = new_pos - current_pos;
#if VERBOSE
		printf("hole from %lu to %lu (%lu bytes)\n", current_pos, new_pos, len);
#endif

		while (current_pos < new_pos) {
			uint64_t this_write_len = new_pos - current_pos;

			if (this_write_len > BUF_SIZE)
				this_write_len = BUF_SIZE;
			pwrite(fd, buf, this_write_len, current_pos);

			current_pos += this_write_len;
		}

/*
		if ((fallocate(fd, FALLOC_FL_KEEP_SIZE|FALLOC_FL_ZERO_RANGE, current_pos, len)) < 0) {
			printf("fallocate returned an error: %m\n");
		}
*/
		holes_chewed++;

		current_pos = new_pos;

	}
	close(fd);

#if VERBOSE
	if (errno == ENXIO)
		printf("looks like we're complete\n");
#endif
	if (! holes_chewed)
		printf("no holes found\n");
	else
		printf("chewed %lu hole%s\n", holes_chewed, holes_chewed == 1 ? "" : "s");

	free(buf);
	return EXIT_SUCCESS;
}
