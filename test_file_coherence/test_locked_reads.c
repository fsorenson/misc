/*
	Frank Sorenson <sorenson@redhat.com>, 2021
*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#define BUF_LEN 4096

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

enum { USE_READS, USE_MMAP };

int usage(const char *exe, int ret) {
	output("usage: %s <filename> <read | mmap>\n", exe);
	return ret;
}
int main(int argc, char *argv[]) {
	struct flock fl= {
		.l_type = F_RDLCK,
		.l_start = 0,
		.l_whence = SEEK_SET,
		.l_len = 0,
	};
	char *filename = argv[1], *map_buf;
	int fd, read_mmap = USE_READS;

	if (argc != 3)
		return usage(argv[0], EXIT_FAILURE);

	if (!strcmp(argv[2], "read"))
		read_mmap = USE_READS;
	else if (!strcmp(argv[2], "mmap"))
		read_mmap = USE_MMAP;
	else
		return usage(argv[0], EXIT_FAILURE);

	if ((fd = open(filename, O_RDONLY)) < 0) {
		output("failed to open file: %m\n");
		return EXIT_FAILURE;
	}
	if (read_mmap == USE_READS)
		map_buf = malloc(BUF_LEN);
	else
		map_buf = (char *)mmap(0, BUF_LEN, PROT_READ, MAP_SHARED, fd, 0);

	while (42) {
		fl.l_type = F_RDLCK;
		fcntl(fd, F_SETLKW, &fl);
		if (read_mmap == USE_READS)
			pread(fd, map_buf, BUF_LEN, 0);

		output("%c", map_buf[0]);
		fl.l_type = F_UNLCK;
		fcntl(fd, F_SETLKW, &fl);
		usleep(100000);
	}

	return EXIT_FAILURE; /* this should be an infinite loop */
}
