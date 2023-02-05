#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>

#define BUF_SIZE (32768)

int main(int argc, char *argv[]) {
	int infd, outfd;
	char buf[BUF_SIZE], outbuf[BUF_SIZE];
	char nullbuf[BUF_SIZE];
	int count, outcount;
	uint64_t size, pos = 0;
	struct statx stx;

	memset(nullbuf, 0, BUF_SIZE);

	if (argc != 3) {
		printf("usage: %s <input_file> <output_file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	if ((infd = open(argv[1], O_RDONLY)) < 0) {
		printf("error opening: %m\n");
		return EXIT_FAILURE;
	}

	statx(infd, "", AT_EMPTY_PATH, STATX_ALL, &stx);
	size = stx.stx_size;

	if ((outfd = open(argv[2], O_RDWR|O_CREAT|O_EXCL, 0644)) < 0) {
		printf("error opening: %m\n");
		return EXIT_FAILURE;
	}

printf("input size: %lu\n", size);

	while ((count = read(infd, buf, BUF_SIZE)) > 0) {
		char *p1 = buf, *p2 = outbuf;
		char *pend = p1 + count;
//printf("read %d\n", count);
		printf("%ld/%ld (%.03lf%%)\r", pos, size, ((double)pos/(double)size)*(double)100);
		fflush(stdout);
		while (p1 < pend) {
			if (*p1 == 0)
				p1++;
			else
				*(p2++) = *(p1++);
		}
		outcount = p2 - outbuf;

		if (outcount)
			write(outfd, outbuf, outcount);
		pos += count;
	}
	close(infd);
	close(outfd);


	return EXIT_SUCCESS;
}
