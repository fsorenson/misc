/*
	Frank Sorenson <sorenson@redhat.com>, 2020

	rhbz1813811_test1 - test whether mapped memory is in core for
		mapped files on nfs.  Unexpected behavior occurs on
		RHEL 7 kernels after flock() is called for the file.
		At completion, RHEL 7 alternates between the mapped
		file being in-core and not in-core; upstream
		appears to always retain the mapped file in-core.

		# gcc rhbz1813811_test1.c -o rhbz1813811_test1 -Wall

		usage: ./rhbz1813811_test1 <test_file> [<loop_count> [<file_size>]]

	# ./rhbz1813811_test1 /mnt/vm7/foo 2 65536
	loop 1
	  open()
	    file: [1111111111111111]: 16/16 - 100.0
	  mmap()
	    file: [1111111111111111]: 16/16 - 100.0
	    map:  [1111111111111111]: 16/16 - 100.0
	  mlockall(MCL_FUTURE) - DISABLED - if enabled:
	    upstream: tests will always pass (regardless of munlockall() calls)
	    RHEL 7.x: tests will always pass (unless munlockall() called
	  mlock() - DISABLED - if enabled:
	    upstream: no new effect
	    RHEL 7.x: test will always fail
	  flock(LOCK_SH)
	    file: DISABLED - if enabled:
	      upstream: no new effect
	      RHEL 7.x: test will always pass
	    map:  [1111111111111111]: 16/16 - 100.0
	  memcpy(map => buffer)
	    file: [0000000000000000]: 0/16 - 0.0
	    map:  [0000000000000000]: 0/16 - 0.0
	  flock(LOCK_UN)
	    file: [0000000000000000]: 0/16 - 0.0
	    map:  [0000000000000000]: 0/16 - 0.0
	  close()
	    file: [0000000000000000]: 0/16 - 0.0
	    map:  [0000000000000000]: 0/16 - 0.0
	  munmap()
	    file: [0000000000000000]: 0/16 - 0.0

	loop 2
	  open()
	    file: [0000000000000000]: 0/16 - 0.0
	  mmap()
	    file: [0000000000000000]: 0/16 - 0.0
	    map:  [0000000000000000]: 0/16 - 0.0
	  mlockall(MCL_FUTURE) - DISABLED - if enabled:
	    upstream: tests will always pass (regardless of munlockall() calls)
	    RHEL 7.x: tests will always pass (unless munlockall() called
	  mlock() - DISABLED - if enabled:
	    upstream: no new effect
	    RHEL 7.x: test will always fail
	  flock(LOCK_SH)
	    file: DISABLED - if enabled:
	      upstream: no new effect
	      RHEL 7.x: test will always pass
	    map:  [0000000000000000]: 0/16 - 0.0
	  memcpy(map => buffer)
	    file: [1111111111111111]: 16/16 - 100.0
	    map:  [1111111111111111]: 16/16 - 100.0
	  flock(LOCK_UN)
	    file: [1111111111111111]: 16/16 - 100.0
	    map:  [0000000011111111]: 8/16 - 50.0
	  close()
	    file: [1111111111111111]: 16/16 - 100.0
	    map:  [1111111111111111]: 16/16 - 100.0
	  munmap()
	    file: [1111111111111111]: 16/16 - 100.0

*/


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

#define DEFAULT_TEST_SIZE 16384
#define DEFAULT_LOOP_COUNT 4

/* could parameterized in the future if desired */
int do_mlockall_future = 0, do_munlockall = 0;
int do_mlock = 0, do_munlock = 0;

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGES_CEIL(len) ((len + PAGE_SIZE - 1) / PAGE_SIZE)

#define RANDOM_STATEBUF_SIZE (4096)
#define RAND_STATE_SIZE (256)
struct random_data random_data;
char *random_statebuf;
int state_pickanum(struct random_data *random_data, int _low, int _high) { /* both inclusive */
	int low, high;
	int spread;
	int r;

	if (_low < _high) { low = _low ; high = _high; }
	else { low = _high; high = _low; }

	spread = high - low;
	random_r(random_data, &r);
	return (r % (spread + 1)) + low;
}
int pickanum(int _low, int _high) { /* both inclusive */
	return state_pickanum(&random_data, _low, _high);
}
void init_rand_state(void) {
	random_statebuf = mmap(NULL, RANDOM_STATEBUF_SIZE, PROT_READ|PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE,
		-1, 0);
	memset(random_statebuf, 0, RAND_STATE_SIZE);
	initstate_r((time(NULL) % INT_MAX),
		random_statebuf, RAND_STATE_SIZE,
		&random_data);
}

void check_mem_mincore(char *mem, int len) {
	unsigned char *mincore_vec;
	int incore_count = 0;
	int i;

	mincore_vec = malloc(PAGES_CEIL(len));
	mincore(mem, len, mincore_vec);

	printf("[");
	for (i = 0 ; i < PAGES_CEIL(len) ; i++) {
		printf("%c", '0' + (mincore_vec[i] & 0x01));
		incore_count += mincore_vec[i] & 0x01;
	}
	printf("]: %d/%d - %.1f\n", incore_count, PAGES_CEIL(len), (incore_count * 1.0) / (PAGES_CEIL(len) * 1.0) * 100.0);

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
void do_one_test(char *buf, char *path, int test_size) {
	char *map;
	int fd;

	printf("  open()\n");
	fd = open(path, O_RDONLY);

	printf("    file: ");
	check_path_mincore(path, test_size);

	printf("  mmap()\n");
	map = mmap(NULL, test_size, PROT_READ, MAP_SHARED, fd, 0);

	printf("    file: ");
	check_path_mincore(path, test_size);
	printf("    map:  ");
	check_mem_mincore(map, test_size);

	if (do_mlockall_future) {
		printf("  mlockall(MCL_FUTURE)\n");
		mlockall(MCL_FUTURE);
		printf("    file: ");
		check_path_mincore(path, test_size);
		printf("    map:  ");
		check_mem_mincore(map, test_size);

		if (do_munlockall) {
			printf("  munlockall()\n");
			munlockall();
			printf("    file: ");
			check_path_mincore(path, test_size);
			printf("    map:  ");
			check_mem_mincore(map, test_size);
		} else {
			printf("  munlockall() - DIABLED - if enabled:\n");
			printf("    upstream: no new effect\n");
			printf("    RHEL 7.x: tests will always fail\n");
		}
	} else {
		printf("  mlockall(MCL_FUTURE) - DISABLED - if enabled:\n");
		printf("    upstream: tests will always pass (regardless of munlockall() calls)\n");
		printf("    RHEL 7.x: tests will always pass (unless munlockall() called\n");
	}

	if (do_mlock) {
		printf("  mlock()\n");
		mlock(map, test_size);
		printf("    file: ");
		check_path_mincore(path, test_size);
		printf("    map:  ");
		check_mem_mincore(map, test_size);

		if (do_munlock) {
			printf("  munlock()\n");
			munlock(map, test_size);
			printf("    file: ");
			check_path_mincore(path, test_size);
			printf("    map:  ");
			check_mem_mincore(map, test_size);
		} else {
			printf("  munlock() - DISABLED\n");
		}
	} else {
		printf("  mlock() - DISABLED - if enabled:\n");
		printf("    upstream: no new effect\n");
		printf("    RHEL 7.x: test will always fail\n");
	}

	printf("  flock(LOCK_SH)\n");
	flock(fd, LOCK_SH);
	if (0) {
		printf("    file: ");
		check_path_mincore(path, test_size);
	} else {
		printf("    file: DISABLED - if enabled:\n");
		printf("      upstream: no new effect\n");
		printf("      RHEL 7.x: test will always pass\n");
	}
	printf("    map:  ");
	check_mem_mincore(map, test_size);

	printf("  memcpy(map => buffer)\n");
	memcpy(buf, map, test_size);
	printf("    file: ");
	check_path_mincore(path, test_size);
	printf("    map:  ");
	check_mem_mincore(map, test_size);


	printf("  flock(LOCK_UN)\n");
	flock(fd, LOCK_UN);
	printf("    file: ");
	check_path_mincore(path, test_size);
	printf("    map:  ");
	check_mem_mincore(path, test_size);

	printf("  close()\n");
	close(fd);
	printf("    file: ");
	check_path_mincore(path, test_size);
	printf("    map:  ");
	check_mem_mincore(map, test_size);

	printf("  munmap()\n");
	munmap(map, test_size);

	printf("    file: ");
	check_path_mincore(path, test_size);


}
void create_file(char *path, int test_size) {
	char buf[2];
	int fd;
	int i;

	buf[1] = '\0';
	fd = open(path, O_CREAT|O_TRUNC|O_RDWR, 0644);
	for (i = 0 ; i < test_size ; i++) { /* fill with random integer characters */
		buf[0] = (char)pickanum('0', '9');
		write(fd, buf, 1);
	}
	fsync(fd);
	close(fd);
}
int main(int argc, char *argv[]) {
	int test_size = DEFAULT_TEST_SIZE;
	int loop_count = DEFAULT_LOOP_COUNT;
	char *path;
	char *buf;
	int i;

	if (argc < 2 || argc > 4) {
		printf("usage: %s <test_file> [<loop_count> [<file_size>]]\n", argv[0]);
		printf("\tdefault loop_count: %d; default file_size: %d\n",
			DEFAULT_LOOP_COUNT, DEFAULT_TEST_SIZE);
		return EXIT_FAILURE;
	}
	path = argv[1];
	if (argc >= 3)
		loop_count = strtol(argv[2], NULL, 10);
	if (argc == 4)
		test_size = strtol(argv[3], NULL, 10);

	buf = malloc(test_size);
	init_rand_state();

	create_file(path, test_size);

	for (i = 0 ; i++ < loop_count ; ) {
		printf("loop %d\n", i);

		do_one_test(buf, path, test_size);

		if (i < loop_count)
			printf("\n");
	}
	free(buf);
	munmap(random_statebuf, RANDOM_STATEBUF_SIZE);

	return EXIT_SUCCESS;
}
