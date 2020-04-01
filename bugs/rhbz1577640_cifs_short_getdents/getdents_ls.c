/*
	Frank Sorenson, <sorenson@redhat.com>  2018

	Test program to call getdents() with specified byte 'count'
	parameter.

	Reproduces bug where directory listing on cifs may miss
	entries when getdents is called with short 'count'

	# gcc -Wall getdents_ls.c -o getdents_ls

	usage:
		getdents_ls [<buf_size> [<path>]]

*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <sys/resource.h>
#include <signal.h>

#define KiB (1024ULL)

struct linux_dirent64 {
	ino64_t		d_ino;
	off64_t		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[];
};

#define exit_fail(args...) do { \
	printf("Error %d: %s - ", errno, strerror(errno)); \
	printf(args); exit(EXIT_FAILURE); } while (0)

int do_test(char *directory, long int buf_size) {
	struct linux_dirent64 *temp_de;
	unsigned long dirent_count = 0;
	char *buf, *bpos;
	int dir_fd;
	int nread;

	buf = malloc(buf_size);

	if ((dir_fd = open(directory, O_RDONLY | O_DIRECTORY)) == -1)
		exit_fail("open call failed");

	for ( ; ; ) {
		nread = syscall(SYS_getdents64, dir_fd, buf, buf_size);

		if (nread == -1)
			exit_fail("getdents call failed");
		if (nread == 0)
			break;

		bpos = buf;
		while (bpos < buf + nread) {
			temp_de = (struct linux_dirent64 *)bpos;
			dirent_count++;

			printf("%s\n", temp_de->d_name);
			bpos += temp_de->d_reclen;
		}
	}
	close(dir_fd);
	free(buf);

	printf("Found %lu entries\n", dirent_count);

	return 0;
}

int main(int argc, char *argv[]) {
	char *directory;
	long int buf_size;

	buf_size = (argc > 1) ? strtol(argv[1], NULL, 10) : (32ULL * KiB);
	directory = (argc > 2) ? argv[2] : ".";

	do_test(directory, buf_size);

	return EXIT_SUCCESS;
}
