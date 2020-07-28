/*
	Frank Sorenson <sorenson@redhat.com>, 2020

	rhbz1813811_test1 - test whether mapped memory is in core for
		mapped files on nfs.  Unexpected behavior occurs on
		RHEL 7 kernels after flock() is called for the file.
		At completion, RHEL 7 alternates between the mapped
		file being in-core and not in-core; upstream
		appears to always retain the mapped file in-core.

		# gcc rhbz1813811_test3.c -o rhbz1813811_test3 -Wall

		usage: ./rhbz1813811_test3 <test_file> [<loop_count> [<file_size>]]


	# ./rhbz1813811_test3 /mnt/vm8/foo 10
	 loop | map                 | file
	    1 | [1111]: 4/4 - 100.0 | [0000]: 0/4 - 0.0
	    2 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
	    3 | [1111]: 4/4 - 100.0 | [0000]: 0/4 - 0.0
	    4 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
	    5 | [1111]: 4/4 - 100.0 | [0000]: 0/4 - 0.0
	    6 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
	    7 | [1111]: 4/4 - 100.0 | [0000]: 0/4 - 0.0
	    8 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
	    9 | [1111]: 4/4 - 100.0 | [0000]: 0/4 - 0.0
	   10 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sys/file.h>
#include <linux/falloc.h>

#define DEFAULT_TEST_SIZE 16384
#define DEFAULT_LOOP_COUNT 4

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGES_CEIL(len) ((len + PAGE_SIZE - 1) / PAGE_SIZE)
#define max(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a > b ? a : b; })

#define FILL_CHARS "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.`~!@#$%^&*()-+=,<.>/?;:'"
static char fill_chars[] = FILL_CHARS;
int pages_required, pages_chars;

void check_mem_mincore(char *mem, int len) {
	unsigned char *mincore_vec;
	int incore_count = 0;
	int i;

	mincore_vec = malloc(pages_required);
	mincore(mem, len, mincore_vec);

	printf("[");
	for (i = 0 ; i < pages_required ; i++) {
		printf("%c", '0' + (mincore_vec[i] & 0x01));
		incore_count += mincore_vec[i] & 0x01;
	}
	printf("]: %*d/%*d - %3.1f", pages_chars, incore_count,
		pages_chars, pages_required,
		(incore_count * 1.0) / (pages_required * 1.0) * 100.0);

	free(mincore_vec);
}

void check_path_mincore(char *path, int len) {
	char *map;
	int fd;

	fd = open(path, O_RDWR);
	map = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);

	check_mem_mincore(map, len);

	munmap(map, len);
	close(fd);
}

int main(int argc, char *argv[]) {
	int test_size = DEFAULT_TEST_SIZE;
	int loop_count = DEFAULT_LOOP_COUNT;
	char *buf, *map, *path;
	int mincore_check_len, loop_chars;
	int fd, i = 0;

	if (argc < 2 || argc > 4) {
		printf("usage: %s <test_file> [<loop_count> [<file_size>]]\n", argv[0]);
		printf("\tdefault loop_count: %d; default file_size: %d\n",
			DEFAULT_LOOP_COUNT, DEFAULT_TEST_SIZE);
		return EXIT_FAILURE;
	}
	path = argv[1];
	if (argc >= 3)
		loop_count = max(strtol(argv[2], NULL, 10), 1);
	if (argc == 4)
		test_size = max(strtol(argv[3], NULL, 10), 1);

	buf = malloc(test_size);



	/* create/display header */
	pages_required = PAGES_CEIL(test_size);
	pages_chars = snprintf(NULL, 0, "%d", pages_required);

	mincore_check_len = snprintf(NULL, 0, "[%0*d]: %d/%d - %3.1f",
		pages_required, 0, pages_required, pages_required, 100.0);
	loop_chars = max(snprintf(NULL, 0, "%d", loop_count), (int)sizeof("loop"));
	printf("%*s | %-*s | %s\n", loop_chars, "loop", mincore_check_len, "map", "file");


	fd = open(path, O_RDONLY);
	map = mmap(NULL, test_size, PROT_READ, MAP_SHARED, fd, 0);
	memcpy(buf, map, test_size);
	while (42) {
		i++;
		printf("%*d | ", loop_chars, i);

/*
		flock(fd, LOCK_SH);
		memcpy(buf, map, test_size);
		flock(fd, LOCK_UN);
*/

		check_mem_mincore(map, test_size);

		printf("\n");
		sleep(1);
	}
	free(buf);
	munmap(map, test_size);
	close(fd);

	return EXIT_SUCCESS;
}
