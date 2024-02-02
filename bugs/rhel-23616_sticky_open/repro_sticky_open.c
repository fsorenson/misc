/*
	Frank Sorenson <sorenson@redhat.com>, 2024

	setup - create a group and two user accounts:
	# groupadd -g 2000 group2000
	# useradd -g 2000 -u 2000 user2000
	# useradd -g 2000 -u 2001 user2001

	with sticky bit on the directory, 777 permissions, opening
	an existing file with O_CREAT when not the owner fails

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

#define ARRAY_SIZE(a) ( sizeof(a)/sizeof(a[0]) )

char *path = DIRECTORY;
int dfd;

int set_protected(int val) {
	char buf = (char)(val + '0');
	int fd, ret = 0;

	if ((fd = open("/proc/sys/fs/protected_regular", O_WRONLY)) < 0) {
		printf("error opening sysctl: %m\n");
		return 1;
	}
	if ((ret = write(fd, &buf, 1)) != 1) {
		printf("error writing %d to sysctl: %m\n", val);
	}
	close(fd);

	return ret == 1 ? 0 : 1;
}

int test_openas(int dfd, uid_t uid, int flags) {
	int fd, status;
	pid_t cpid;

	if ((cpid = fork()) == 0) {
		if (setgid(GID))
			printf("      error with setgid: %m\n");
		if (setuid(uid))
			printf("      error with setuid: %m\n");

		if ((fd = openat(dfd, FILENAME, flags, 0664)) < 0) {
			printf("      error opening '%s/%s': %m\n", path, FILENAME);
			exit(EXIT_FAILURE);
		}
		close(fd);
		exit(EXIT_SUCCESS);
	}
	waitpid(cpid, &status, 0);
	return 0;
}
#define do_test(flags) do { \
	printf("    testing open as uid %d with open flags %s\n", UID2, #flags); \
	ret += test_openas(dfd, UID2, flags); \
} while (0)

int test_dir_mode(int mode) {
	int ret = 0;

	printf("  setting directory mode to %o\n", mode);
	if ((fchmod(dfd, mode))) {
		printf("error changing mode of '%s' to %o: %m\n", path, mode);
		return 1;
	}

	do_test(O_WRONLY);
	do_test(O_WRONLY|O_CREAT);

	return ret;
}

int test_protected(int val) {
	int modes[] = { 0777, 01777 }, i, ret = 0;

	printf("setting sysctl fs.protected_regular to %d\n", val);
	set_protected(val);

	for (i = 0 ; i < ARRAY_SIZE(modes) ; i++) {
		ret += test_dir_mode(modes[i]);
		printf("\n");
	}

	return ret;
}

int do_testing(void) {
	int i, ret = 0;

	for (i = 0 ; i <= 2 ; i++)
		ret += test_protected(i);

	return ret;
}


int main(int argc, char *argv[]) {
	int fd, ret = 0;

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

	ret += do_testing();

	return ret;
}
