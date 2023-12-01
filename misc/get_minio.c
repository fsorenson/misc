#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <unistd.h>

#define BBSIZE	512

int get_minio(int fd) {
	long pagesz = sysconf(_SC_PAGESIZE);
	int minsz;
	void *buf;

	posix_memalign(&buf, pagesz, pagesz);

	for (minsz = BBSIZE ; minsz < pagesz ; minsz <<= 1)
		if ((pread64(fd, buf, minsz, 0)) >= 0)
			break;
	free(buf);
	return minsz;
}

int main(int argc, char *argv[]) {
	int fd;

	if ((fd = open(argv[1], O_RDONLY|O_DIRECT)) < 0) {
		printf("error opening: %m\n");
		return EXIT_FAILURE;
	}
	printf("minimum IO: %d\n", get_minio(fd));
	close(fd);

	return EXIT_SUCCESS;
}
