/*
	Frank Sorenson <sorenson@redhat.com>, 2024
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/fsuid.h>
#include <fcntl.h>
#include <sys/wait.h>

#define UID1 2000
#define UID2 2001
#define GID 2000

#define DIRECTORY "/tmp/testdir"
#define FILENAME "testfile2000"
#define FULLPATH DIRECTORY "/" FILENAME

char *path = DIRECTORY;

int test_openas(int dfd, uid_t uid, int flags) {
	int fd, status;
	pid_t cpid;

	if ((cpid = fork()) == 0) {
		if (setgid(GID))
			printf("error with setgid: %m\n");
		if (setuid(uid))
			printf("error with setuid: %m\n");

		if ((fd = openat(dfd, FILENAME, flags, 0664)) < 0) {
			printf("error opening '%s/%s': %m\n", path, FILENAME);
			exit(EXIT_FAILURE);
		}
		close(fd);
		exit(EXIT_SUCCESS);
	}
	waitpid(cpid, &status, 0);
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
	int dfd, fd;

	if (argc > 1)
		path = argv[1];

	printf("testing with directory '%s'\n", path);
	printf("\n");

	umask(0002);

	mkdir(path, 01777);
	chown(path, 0, 0);

	if ((dfd = open(path, O_RDONLY)) < 0) {
		printf("error opening '%s': %m\n", path);
		return EXIT_FAILURE;
	}
	unlinkat(dfd, FILENAME, 0);
	if ((fd = openat(dfd, FILENAME, O_CREAT|O_WRONLY, 0664)) < 0) {
		printf("error creating/opening '%s': %m\n", FILENAME);
		return EXIT_FAILURE;
	}
	fchown(fd, UID1, GID);
	close(fd);

	printf("setting directory mode to 1777\n");
	if ((fchmod(dfd, 01777)))
		printf("error changing mode of '%s' to 01777: %m\n", path);

	printf("testing open as uid %d with open flags O_WRONLY|O_CREAT\n", UID2);
	test_openas(dfd, UID2, O_WRONLY|O_CREAT);

	printf("\n");

	printf("setting directory mode to 0777\n");
	if ((fchmod(dfd, 0777)))
		printf("error changing mode of '%s' to 0777: %m\n", path);

	printf("testing open as uid %d with open flags O_WRONLY|O_CREAT\n", UID2);
	test_openas(dfd, UID2, O_WRONLY|O_CREAT);

	return EXIT_SUCCESS;
}
