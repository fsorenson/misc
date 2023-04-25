/*
	Frank Sorenson <sorenson@redhat.com>, 2023

	test opening a file more than once; the server is expected
	    to return an incremented seqid with each OPEN reply.

	In a customer case, the nfs server was returning the same
	    sequence id for all the OPENs, resulting in the client
	    delaying for 5 seconds on each subsequent open.

	It is expected that delegations would result in just a
	    single OPEN call, so this issue should not be seen
	    when delegations are enabled.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#define TESTFILE "testfile.grib2"
#define BUFSIZE 1048576

int main(int argc, char *argv[]) {
	struct timespec start_time, stop_time;
	char *testfile = TESTFILE;
	char buf[BUFSIZE];
	int fd1 = -1, fd2 = -1;
	struct stat st;

	if (argc == 2)
		testfile = argv[1];

	printf("opening test file '%s'\n", testfile);

	clock_gettime(CLOCK_REALTIME, &start_time);
	if ((fd1 = openat(AT_FDCWD, testfile, O_RDONLY)) < 0) { // 09:59:07.328334
		printf("error opening test file: %m\n");
		return EXIT_FAILURE;
	}
	lseek(fd1, 0, SEEK_CUR);
	fstat(fd1, &st);
	read(fd1, buf, 8192);
	lseek(fd1, 0, SEEK_CUR);
	read(fd1, buf, 73728);
	read(fd1, buf, 8192);
	lseek(fd1, 0, SEEK_CUR);

	fd2 = openat(AT_FDCWD, testfile, O_RDONLY); // 09:59:07.445803
	fstat(fd2, &st);
	lseek(fd2, 0, SEEK_SET);
	read(fd2, buf, 8192);
	read(fd2, buf, 73728);
	read(fd2, buf, 8192);
	lseek(fd2, 0, SEEK_CUR);
	close(fd2);

	fd2 = openat(AT_FDCWD, testfile, O_RDONLY); // 09:59:12.995454
	fstat(fd2, &st);
	lseek(fd2, 0, SEEK_SET);
	read(fd2, buf, 8192);
	read(fd2, buf, 73728);
	read(fd2, buf, 8192);
	close(fd2);

	fd2 = openat(AT_FDCWD, testfile, O_RDONLY); // 09:59:18.126972
	fstat(fd2, &st);
	lseek(fd2, 0, SEEK_SET);
	read(fd2, buf, 8192);
	read(fd2, buf, 73728);
	read(fd2, buf, 8192);
	close(fd2);

	fd2 = openat(AT_FDCWD, testfile, O_RDONLY); // 09:59:23.197468
	fstat(fd2, &st);
	lseek(fd2, 0, SEEK_SET);
	read(fd2, buf, 8192);
	read(fd2, buf, 73728);
	read(fd2, buf, 8192);
	close(fd2);

	close(fd1);
	clock_gettime(CLOCK_REALTIME, &stop_time);

	stop_time.tv_sec -= start_time.tv_sec;
	if (stop_time.tv_nsec < start_time.tv_nsec) {
		stop_time.tv_sec--;
		stop_time.tv_nsec += 1000000000ULL;
	}
	stop_time.tv_nsec -= start_time.tv_nsec;

	printf("elapsed time: %lu.%09lu\n", stop_time.tv_sec, stop_time.tv_nsec);

	if (stop_time.tv_sec > 1)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
