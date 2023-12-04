#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <unistd.h>

#define BBSIZE	512

struct config {
	int fd;
	long pagesz;
	void *buf;
	int minsz;
	int offset;
	int addralign;
} config;

int get_minio() {
	for (config.minsz = BBSIZE ; config.minsz < config.pagesz ; config.minsz <<= 1)
		if ((pread64(config.fd, config.buf, config.minsz, 0)) >= 0)
			break;
	return config.minsz;
}
int get_offalign() {
	for (config.offset = BBSIZE ; config.offset < config.pagesz ; config.offset <<= 1) {
		if ((pread(config.fd, config.buf, config.minsz, config.offset)) >= 0)
			break;
	}
	return config.offset;
}
int get_addralign() {
	uint64_t addr;

	for (config.addralign = BBSIZE ; config.addralign <= config.pagesz ; config.addralign <<= 1) {
//		addr = (uint64_t)config.buf + ((config.pagesz * 2) & (uint64_t)(~(align - 1)));
//		addr = (uint64_t)config.buf + ((config.pagesz * 2) & (uint64_t)(~(align - 1)));
		addr = (uint64_t)config.buf + (config.pagesz * 2) - config.addralign;

		if ((pread(config.fd, (void *)addr, config.minsz, 0)) >= 0)
			return config.addralign;
	}
	return 0;
}

int main(int argc, char *argv[]) {
	config.pagesz = sysconf(_SC_PAGESIZE);

	posix_memalign(&config.buf, config.pagesz, config.pagesz * 3);
	memset(config.buf, 0, config.pagesz * 3);

	if ((config.fd = open(argv[1], O_CREAT|O_RDONLY|O_DIRECT)) < 0) {
		printf("error opening: %m\n");
		return EXIT_FAILURE;
	}
	pwrite(config.fd, config.buf, config.pagesz * 3, 0);
	printf("minimum IO: %d\n", get_minio());
	printf("offset alignment: %d\n", get_offalign());
	printf("addralign: %d\n", get_addralign());


	close(config.fd);

	return EXIT_SUCCESS;
}
