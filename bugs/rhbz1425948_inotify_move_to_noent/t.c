#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>


#define TEST_NUM 2

int main(int argc, char *argv[]) {
	int fd;

#if TEST_NUM == 1
	struct timespec ts;

	ts.tv_sec = 5;
	ts.tv_nsec = 0;


	mkdir("staging/testdir/", 0755);
	fd = open("staging/testdir/testfile", O_RDWR | O_CREAT | O_TRUNC, 0644);
	unlink("staging/testdir/testfile");

	rename("staging/testdir", "final/testdir");
	nanosleep(&ts, NULL);

	close(fd);
#elif TEST_NUM == 2

	mkdir("staging/testdir/", 0755);
	fd = open("staging/testdir/testfile", O_RDWR | O_CREAT | O_TRUNC, 0644);
	close(fd);
	rename("staging/testdir/testfile", "final/testdir/testfile");
	unlink("final/testdir/testfile");
#endif

	return EXIT_SUCCESS;
}

