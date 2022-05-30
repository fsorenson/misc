#ifndef _GNU_SOURCE
#define _GNU_SOURCE 
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)

#define NUM_THREADS 5
#define TESTFILE_SIZE (500ULL * MiB)
#define FILENAME_PATTERN "test_file-%d"

int do_thread_work(int thread_id) {
	int fd;
	char *filename;

	asprintf(&filename, FILENAME_PATTERN, thread_id);

	fd = open(filename, O_CREAT|O_TRUNC|O_RDWR, 0666);
	while (1) {
		ftruncate(fd, TESTFILE_SIZE);
		posix_fadvise(fd, 0, TESTFILE_SIZE,
			POSIX_FADV_WILLNEED|POSIX_FADV_SEQUENTIAL);
		truncate(filename, 0);
	}
	return EXIT_SUCCESS;
	/* is it really succcess if we break out of an infinite loop? */
}

int main(int argc, char *argv[]) {
	struct timespec ts = { 60, 0 };
	int i;

	for (i = 0 ; i < NUM_THREADS ; i++)
		if (! fork())
			return do_thread_work(i);
	while (1)
		nanosleep(&ts, 0);

	return EXIT_SUCCESS; /* again? */
}
