/*
	Frank Sorenson <sorenson@redhat.com>, 2016

	reproducer for bugzilla 1322823 - deadlock

	usually able to reproduce the issue within 20 seconds
	with 2-3 threads (but is sometimes more stubborn to
	reproduce).  Number of threads and map size may need
	adjustment.

	# gcc test_nfs_trunc.c -o test_fs_trunc
	# ./test_nfs_trunc [ </path/to/file> [ </path/to/file [ ... ]]]
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (MiB * KiB)

#define MAP_SIZE (5ULL * MiB)
#define TRUNC_SIZE (0ULL)
#define DEBUG 1

#define exit_fail(args...) do { \
	printf(args); fflush(stdout); exit(EXIT_FAILURE); } while (0)

#define error_exit_fail(args...) do { \
	printf("Error %d: %s - ", errno, strerror(errno)); \
	exit_fail(args); \
	} while (0)

#if DEBUG
#define debug(args...) do { \
	printf(args); fflush(stdout); \
	} while (0)
#else
#define debug(args...) do { } while (0)
#endif

void do_work(char *filename) {
	char *map;
	int fd;

	while (1) {
		debug(".");
		if ((fd = open(filename, O_RDWR | O_CREAT | O_TRUNC | O_NONBLOCK, 0644)) < 0)
			error_exit_fail("opening test file '%s'\n", filename);

		if (ftruncate(fd, MAP_SIZE) != 0)
			error_exit_fail("truncating test file to %llu\n", MAP_SIZE);
		if ((map = mmap(NULL, MAP_SIZE, PROT_WRITE, MAP_SHARED,
			fd, 0)) == MAP_FAILED)
			error_exit_fail("calling mmap\n");
		memset(map, 0xaa, MAP_SIZE);
		munmap(map, MAP_SIZE);
		if (ftruncate(fd, TRUNC_SIZE) != 0)
			error_exit_fail("truncating test file '%s' to %llu\n",
				filename, TRUNC_SIZE);
		close(fd);
	}
}

int main(int argc, char *argv[]) {
	pid_t cpid;
	int i;

	for (i = 1 ; i < argc ; i ++) {
		if ((cpid = fork()) == 0) {
			do_work(argv[i]);
			return EXIT_SUCCESS;
		}
	}
	pause();
	return EXIT_SUCCESS;
}
