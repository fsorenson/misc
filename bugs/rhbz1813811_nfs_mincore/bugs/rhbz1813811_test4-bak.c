/*
	Frank Sorenson <sorenson@redhat.com>, 2020

	rhbz1813811_test1 - test whether mapped memory is in core for
		mapped files on nfs.  Unexpected behavior occurs on
		RHEL 7 kernels after flock() is called for the file.
		At completion, RHEL 7 alternates between the mapped
		file being in-core and not in-core; upstream
		appears to always retain the mapped file in-core.

		# gcc rhbz1813811_test3.c -o rhbz1813811_test3 -Wall

		usage: ./rhbz1813811_test3 [ -c ] [ -l ] <test_file> [<loop_count> [<file_size>]]
			default loop_count: 4; default file_size: 16384
			-c specifies to create the file
			-l specifies to use locking

		use '-c' to create the file _once_ (or use an existing file)
		if '-l' is specified, the proram will test both 

 [root@vm7 tmp]# ./rhbz1813811_test4 
usage: ./rhbz1813811_test4 <test_file> [ -c ] [ -l ] [<loop_count> [<file_size>]]



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
#include <stdbool.h>
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
#include <mcheck.h>

#define DEFAULT_TEST_SIZE 16384
#define DEFAULT_LOOP_COUNT 4

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGES_CEIL(len) ((len + PAGE_SIZE - 1) / PAGE_SIZE)
#define min(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a < b ? a : b; })
#define max(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a > b ? a : b; })

#define FILL_CHARS "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.`~!@#$%^&*()-+=,<.>/?;:'"
static char fill_chars[] = FILL_CHARS;
int pages_required, pages_chars;
unsigned char *mincore_vec = NULL;

void check_mem_mincore(char *mem, int len) {
	int incore_count = 0;
	int i;

	memset(mincore_vec, 0, pages_required);
	mincore(mem, len, mincore_vec);

	printf("[");
	for (i = 0 ; i < pages_required ; i++) {
		printf("%c", '0' + (mincore_vec[i] & 0x01));
		incore_count += mincore_vec[i] & 0x01;
	}
	printf("]: %*d/%*d - %3.1f", pages_chars, incore_count,
		pages_chars, pages_required,
		(incore_count * 1.0) / (pages_required * 1.0) * 100.0);
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

#define out_fail(args...) do { \
	printf(args); \
	ret = EXIT_FAILURE; \
	goto out; \
} while (0)

int main(int argc, char *argv[]) {
	bool create_file = false, use_locking = false, use_map2 = false;
	int loop_count = DEFAULT_LOOP_COUNT;
	long int test_size = 0;
	int mincore_check_len, loop_chars;
	char *buf, *map = NULL, *map2 = NULL, *path = NULL;
	int opt, fd = -1, fd2 = -1, i;
	int ret = EXIT_SUCCESS;
	struct stat st;

mtrace();

	while ((opt = getopt(argc, argv, "cl2")) != -1) {
		switch (opt) {
			case 'c': create_file = true; break;
			case 'l': use_locking = true; break;
			case '2': use_map2 = true; break;
			default: break;
		}
	}

	if (optind < argc - 3 || optind > argc - 1) {
		printf("usage: %s <test_file> [ -c ] [ -l ] [<loop_count> [<file_size>]]\n", argv[0]);
		printf("\tdefault loop_count: %d; default file_size: %d\n",
			DEFAULT_LOOP_COUNT, DEFAULT_TEST_SIZE);
		printf("\t-c specifies to create the file\n");
		printf("\t-l specifies to use locking\n");
//		out_fail("");
//		return EXIT_FAILURE;
		goto out;
	}

	path = argv[optind];

	if (optind < argc - 1)
		loop_count = max(strtol(argv[++optind], NULL, 10), 1);
	if (optind < argc - 1)
		test_size = max(strtol(argv[++optind], NULL, 10), 1);

	buf = malloc(test_size);

	if (test_size < 1 && create_file)
		test_size = DEFAULT_TEST_SIZE;

	/* create/populate the file */
	if (create_file) {
		buf[1] = '\0';
		if ((fd = open(path, O_CREAT|O_TRUNC|O_RDWR, 0644)) < 0) {
out_fail("Unable to create file '%s': %m\n", path);
//			printf("Unable to create file '%s': %m\n", path);
//			ret = EXIT_FAILURE;
//			goto out;
		}
		ftruncate(fd, test_size);
		map = mmap(NULL, test_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		for (i = 0 ; i < test_size ; i++) {
			map[i] = fill_chars[i % (sizeof(fill_chars) - 1)];
		}
		munmap(map, test_size);
		map = NULL;

		fsync(fd);
		close(fd);
		fd = -1;
	}

	if ((stat(path, &st)) < 0)
		out_fail("unable to stat file '%s': %m\n", path);
	if (test_size < 1)
		test_size = st.st_size;
	if (st.st_size < 1)
		out_fail("test file '%s' is too small: %ld\n", path, st.st_size);
	test_size = max(st.st_size, test_size);

	/* create/display header */
	pages_required = PAGES_CEIL(test_size);
	pages_chars = snprintf(NULL, 0, "%d", pages_required);

	mincore_check_len = snprintf(NULL, 0, "[%0*d]: %d/%d - %3.1f",
		pages_required, 0, pages_required, pages_required, 100.0);
	loop_chars = max(snprintf(NULL, 0, "%d", loop_count), (int)sizeof("loop"));

	if ((mincore_vec = malloc(pages_required * 100)) == NULL)
		out_fail("failed to malloc: %m\n");
printf("allocated vector for %d pages at %p\n", pages_required, mincore_vec);

	if (use_locking)
		printf("%*s | %-*s | %s\n", loop_chars, "loop", mincore_check_len, "map", "file");
	else
		printf("%*s | %s\n", loop_chars, "loop", "file");

	if ((fd = open(path, O_RDONLY)) < 0)
		out_fail("unable to open the file '%s': %m\n", path);
	if ((map = mmap(NULL, test_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED)
		out_fail("unable to mmap(fd...): %m\n");
	if (use_map2) {
		if ((fd2 = open(path, O_RDONLY)) < 0)
			out_fail("unable to open the file '%s': %m\n", path);
		if ((map2 = mmap(NULL, test_size, PROT_READ, MAP_SHARED, fd2, 0)) == MAP_FAILED)
			out_fail("unable to mmap(fd2...): %m\n");

	}
	if ((buf = malloc(test_size)) < 0)
		out_fail("unable to allocate buffer of %ld bytes\n", test_size);

	for (i = 0 ; i++ < loop_count ; ) {
		printf("%*d | ", loop_chars, i);


		if (use_locking) {
			flock(fd, LOCK_SH);
			memcpy(buf, map, test_size);
//			madvise(map, test_size, MADV_WILLNEED);
printf("\n");
fflush(stdout);
free(mincore_vec);
mincore_vec = malloc(pages_required * 100);
			flock(fd, LOCK_UN);
			check_mem_mincore(map, test_size);
			printf(" | ");
		}
		check_path_mincore(path, test_size);

		printf("\n");

		if (use_map2) {
			printf("    map2: ");
			check_mem_mincore(map2, test_size);
			printf("\n");
		}

		if (i < loop_count)
			sleep(1);
	}

out:
	if (mincore_vec)
		free(mincore_vec);

	if (buf)
		free(buf);

	if (map2)
		munmap(map2, test_size);
	if (fd2 >= 0)
		close(fd2);
	if (map)
		munmap(map, test_size);
	if (fd >= 0)
		close(fd);


	return ret;
}
