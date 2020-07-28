/*
	Frank Sorenson <sorenson@redhat.com>, 2020

	rhbz1813811_test1 - test whether mapped memory is in core for
		mapped files on nfs.  Unexpected behavior occurs on
		RHEL 7 kernels after flock() is called for the file.
		At completion, RHEL 7 alternates between the mapped
		file being in-core and not in-core; upstream
		appears to always retain the mapped file in-core.

		# gcc rhbz1813811_test3.c -o rhbz1813811_test3 -Wall

		usage: ./rhbz1813811_test3 [ -c ] [ -f ] [ -l [ -2 ] ] [<loop_count> [<file_size>]]
			default loop_count: 4; default file_size: 16384
			-c specifies to create the file
			-l specifies to use locking

		use '-c' to create the file _once_ (or use an existing file)
		if '-l' is specified, lock/unlock the file
		if '-2' is specified, test a second map on the locking/unlocking fd (requires '-l')
		if '-f' is specified, test a map on a second open fd

	# ./rhbz1813811_test4
	usage: ./rhbz1813811_test4 <test_file> [ -c ] [ -f ] [ -l [ -2 ] ] [<loop_count> [<file_size>]]
		default loop_count: 4; default file_size: 16384
		-c specifies to create the file
		-l specifies to use locking
		-2 specifies to use 2nd map on locking fd (requires '-l')
		-f specifies to use map on second fd

	# ./rhbz1813811_test3 /mnt/vm8/foo 5
	 loop | map                 | file
	    1 | [1111]: 4/4 - 100.0 | [0000]: 0/4 - 0.0
	    2 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
	    3 | [1111]: 4/4 - 100.0 | [0000]: 0/4 - 0.0
	    4 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
	    5 | [1111]: 4/4 - 100.0 | [0000]: 0/4 - 0.0

	# ./rhbz1813811_test4 -cl2f /mnt/vm8/foo 5
	 loop | map on locked fd    | 2nd map on lock fd  | map on second fd    | map of reopened fd 
	    1 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [0000]: 0/4 -   0.0 | [0000]: 0/4 -   0.0
	    2 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
	    3 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [0000]: 0/4 -   0.0 | [0000]: 0/4 -   0.0
	    4 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
	    5 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [0000]: 0/4 -   0.0 | [0000]: 0/4 -   0.0
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
#include <ctype.h>

#define DEFAULT_TEST_SIZE 16384
#define DEFAULT_LOOP_COUNT 4

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGES_CEIL(len) ((len + PAGE_SIZE - 1) / PAGE_SIZE)
#define min(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a < b ? a : b; })
#define max(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a > b ? a : b; })

#define do_free(_ptr) do { if (_ptr) free(_ptr); _ptr = NULL; } while (0)
#define do_close(_fd) do { if (_fd >= 0) close(_fd); _fd = -1; } while (0)
#define do_munmap(_ptr, _size) do { if (_ptr) munmap(_ptr, _size); _ptr = NULL; } while (0)

//#define FILL_CHARS "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.`~!@#$%^&*()-+=,<.>/?;:'"
#define FILL_CHARS "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
static char fill_chars[] = FILL_CHARS;
int current_index = 0;
char *buf = NULL;

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
	printf("]: %*d/%*d - %5.1f", pages_chars, incore_count,
		pages_chars, pages_required,
		(incore_count * 1.0) / (pages_required * 1.0) * 100.0);
}

void _check_path_mincore(char *path, int len, bool rdwr) {
	char *map;
	int fd;

	fd = open(path, rdwr ? O_RDWR : O_RDONLY);
	map = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
	check_mem_mincore(map, len);
	munmap(map, len);
	close(fd);
}

void check_path_mincore_ro(char *path, int len) {
	_check_path_mincore(path, len, false);
}
void check_path_mincore_rw(char *path, int len) {
	_check_path_mincore(path, len, true);
}
void check_path_mincore(char *path, int len) {
	check_path_mincore_ro(path, len);
}

#define out_fail(args...) do { \
	printf(args); \
	ret = EXIT_FAILURE; \
	goto out; \
} while (0)

#define get_optional() ({ \
	char *ptr = optarg ? optarg : argv[optind]; \
	if (optarg || argv[optind]) \
		optind++; \
	ptr; \
})

void usage(int argc, char *argv[]) {
	printf("usage: %s <test_file> [ -c [ <file_size> ] ] [ -f [ -r ] ] [ -l [ -2 ] ] [ <loop_count> ]\n", argv[0]);
	printf("\tdefault loop_count: %d; default file_size (when creating): %d\n",
		DEFAULT_LOOP_COUNT, DEFAULT_TEST_SIZE);
	printf("\t-c [ <file_size> ] specifies creation of the file (and possibly size\n");
	printf("\t-l specifies to use locking\n");
	printf("\t-2 specifies to use 2nd map on locking fd (requires/enables '-l')\n");
	printf("\t-f specifies to use map on second fd\n");
	printf("\t-r specifies to repeatedly map/unmap on second fd\n");
}

int main(int argc, char *argv[]) {
	bool create_file = false, use_locking = false, use_rdwr = false;

	bool use_fd3_map = false;
	char *fd_ro_map = NULL, *fd_lk_map1 = NULL, *fd_lk_map2 = NULL, *remap = NULL, *fd3_map = NULL, *path = NULL;
	int loop_count = DEFAULT_LOOP_COUNT;
	int mincore_check_len, loop_chars;
	int opt, fd_lk = -1, fd_ro = -1, fd3 = -1, i;
	char *optptr;
	int ret = EXIT_SUCCESS;
	long int test_size = 0;
	struct stat st;

	while ((opt = getopt(argc, argv, "hc::wl3")) != -1) {
		switch (opt) {
			case 'c':
				optptr = get_optional();
				create_file = true;
				if (optptr && strlen(optptr) && isdigit(optptr[0]))
					test_size = max(strtol(optptr, NULL, 10), 1);
				else {
					optind--;
					test_size = DEFAULT_TEST_SIZE;
				}
				break;
			case 'l': use_locking = true; break;
			case '3': use_fd3_map = true; break;
			case 'w': use_rdwr = true; break;
			case 'h': usage(argc, argv); goto out; break;
			default: break;
		}
	}
//	if (use_rdwr && !use_locking)
//		out_fail("read-write option specified, but locking is not requeste

/*
        map on RO fd1         map2 on fd1           remap fd1             map on RO fd2         open RO/close fd
        map on RW fd1         map2 on fd1           remap fd1             map on RO fd2         open RO/close fd
 loop | map on locked fd    | 2nd map on lock fd  | remap locked fd     | map on 2nd fd       | open RO/close fd   
    1 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
    2 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
    3 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
    4 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0 | [1111]: 4/4 - 100.0
*/


	if (optind < argc - 2 || optind > argc - 1) {
		usage(argc, argv);
		ret = EXIT_FAILURE;
		goto out;
	}

	path = argv[optind];

	if (optind < argc - 1)
		loop_count = max(strtol(argv[++optind], NULL, 10), 1);

	/* create/populate the file */
	if (create_file) {
		if ((fd_lk = open(path, O_CREAT|O_TRUNC|O_RDWR, 0644)) < 0)
			out_fail("Unable to create file '%s': %m\n", path);
		if ((ftruncate(fd_lk, test_size)) < 0)
			out_fail("unable to truncate file '%s' to %ld bytes: %m\n",
				path, test_size);
		if ((fd_lk_map1 = mmap(NULL, test_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd_lk, 0)) == MAP_FAILED)
			out_fail("unable to mmap(fd_lk...) for newly-created file: %m\n");
//		for (i = 0 ; i < test_size ; i++)
//			fd_lk_map1[i] = fill_chars[i % (sizeof(fill_chars) - 1)];
		memset(fd_lk_map1, fill_chars[current_index], test_size);
		do_munmap(fd_lk_map1, test_size);

		fsync(fd_lk);
		do_close(fd_lk);
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

	if ((mincore_vec = malloc(pages_required)) == NULL)
		out_fail("failed to malloc: %m\n");

	if ((buf = malloc(test_size)) == NULL)
		out_fail("unable to malloc %ld-byte buffer: %m\n", test_size);
	printf("%*s", loop_chars, "loop");


	printf(" | %-*s", mincore_check_len, "map on RDONLY fd");
	printf(" | %-*s", mincore_check_len, "remap RDONLY fd");

	if (use_locking) {
		if (use_rdwr) {
			printf(" | %-*s", mincore_check_len, "map on RDWR fd");
			printf(" | %-*s", mincore_check_len, "map2 on RDWR fd");
			printf(" | %-*s", mincore_check_len, "remap RDWR fd");

		} else {
			printf(" | %-*s", mincore_check_len, "map on RDONLY fd");
			printf(" | %-*s", mincore_check_len, "map2 on RDONLY fd");
			printf(" | %-*s", mincore_check_len, "remap RDONLY fd");
		}
	}


	if (use_fd3_map)
		printf(" | %-*s", mincore_check_len, "map on 3rd fd");

	printf(" | %-*s", mincore_check_len, "open RO/close fd");
//	printf(" | %-*s", mincore_check_len, "open RW/close fd");
	printf("\n");


	if ((fd_ro = open(path, O_RDONLY)) < 0)
		out_fail("unable to open the file '%s': %m\n", path);
	if ((fd_ro_map = mmap(NULL, test_size, PROT_READ, MAP_SHARED, fd_ro, 0)) == MAP_FAILED)
		out_fail("unable to mmap(fd_ro...): %m\n");


	if ((fd_lk = open(path, use_rdwr ? O_RDWR : O_RDONLY)) < 0)
		out_fail("unable to open the file '%s': %m\n", path);
//	if ((fd_lk_map1 = mmap(NULL, test_size, PROT_READ, MAP_SHARED, fd_lk, 0)) == MAP_FAILED)
	if ((fd_lk_map1 = mmap(NULL, test_size, use_rdwr ? PROT_READ|PROT_WRITE : PROT_READ, MAP_SHARED, fd_lk, 0)) == MAP_FAILED)
		out_fail("unable to mmap(fd...): %m\n");


	if (use_locking) {
		if ((fd_lk_map2 = mmap(NULL, test_size, PROT_READ, MAP_SHARED, fd_lk, 0)) == MAP_FAILED)
			out_fail("unable to mmap(fd...) a second time: %m\n");
	}
	if (use_fd3_map) {
		if ((fd3 = open(path, O_RDWR)) < 0)
			out_fail("unable to open the file '%s': %m\n", path);
		if ((fd3_map = mmap(NULL, test_size, PROT_READ, MAP_SHARED, fd3, 0)) == MAP_FAILED)
			out_fail("unable to mmap(fd3...): %m\n");
	}

	memset(buf, fill_chars[current_index], test_size);
	for (i = 0 ; i++ < loop_count ; ) {
//		memset(buf, fill_chars[current_index], test_size);
//		memset(fd_lk_map1, fill_chars[current_index], test_size);


		buf[0] = fill_chars[current_index];
		memset(buf, fill_chars[current_index], test_size);


		printf("%*d", loop_chars, i);

		if (use_locking) {
			printf(" | ");

/* flock mode does not seem relevant */
//			if ((flock(fd_lk, LOCK_SH)) < 0) {
//			if ((flock(fd_lk, LOCK_EX)) < 0) {
			if ((flock(fd_lk, use_rdwr ? LOCK_EX : LOCK_SH)) < 0) {
				printf("error calling flock(): %m\n");
			}
//			madvise(fd_lk_map1, test_size, MADV_WILLNEED);

if (use_rdwr) {
	memcpy(fd_lk_map1, buf, test_size);
}
			memcpy(buf, fd_lk_map1, test_size);
			if ((flock(fd_lk, LOCK_UN)) < 0)
				printf("error calling flock(): %m\n");
			check_mem_mincore(fd_lk_map1, test_size);
		}


		printf(" | ");
		check_mem_mincore(fd_ro_map, test_size);


if ((fd_ro_map[0] != buf[0]) || (memcmp(buf, fd_ro_map, test_size))) {
	printf("NOT A MATCH: %c\n", fd_ro_map[0]);

}

		if ((remap = mmap(NULL, test_size, PROT_READ, MAP_SHARED, fd_ro, 0)) == MAP_FAILED)
			out_fail("unable to re-mmap(fd_ro...): %m\n");
		printf(" | ");
		check_mem_mincore(remap, test_size);
		do_munmap(remap, test_size);


		if (use_locking) {
			printf(" | ");
			check_mem_mincore(fd_lk_map2, test_size);

			if ((remap = mmap(NULL, test_size, PROT_READ, MAP_SHARED, fd_lk, 0)) == MAP_FAILED)
				out_fail("unable to re-mmap(fd_lk...): %m\n");
			printf(" | ");
			check_mem_mincore(remap, test_size);
			do_munmap(remap, test_size);
		}



		if (use_fd3_map) {
			printf(" | ");
			check_mem_mincore(fd3_map, test_size);
		}

		printf(" | ");
		check_path_mincore_ro(path, test_size);

//		printf(" | ");
//		check_path_mincore_rw(path, test_size);
		printf("\n");

		if (i < loop_count)
			sleep(1);
		if (use_rdwr) {
			current_index = (current_index + 1) % sizeof(fill_chars);
			memset(fd_lk_map1, fill_chars[current_index], test_size);
		}
	}

out:

	do_free(buf);
	do_free(mincore_vec);
	do_munmap(fd3_map, test_size);
	do_munmap(fd_ro_map, test_size);
	do_close(fd3);
	do_close(fd_ro);
	do_munmap(remap, test_size);
	do_munmap(fd_lk_map2, test_size);
	do_munmap(fd_lk_map1, test_size);
	do_close(fd_lk);

	return ret;
}
