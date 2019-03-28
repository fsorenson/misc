/*
	test program for unaligned O_DIRECT aio writes on EXT4

	Frank Sorenson - <sorenson@redhat.com>
	2019

	requires libaio, ext4 filesystem

		# gcc aio_repro.c -o aio_repro -laio

	in a directory on ext4:

		# ./aio_repro testfile


	the program will output either SUCCESS and exit with 0 status, or
	output FAILURE and exit with non-zero exit status


	the test file can also be checked with hexdump.  The file should
	contain only non-zero bytes:

# hexdump -C testfile 
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000200  31 31 31 31 31 31 31 31  31 31 31 31 31 31 31 31  |1111111111111111|
*
00001200
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libaio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

#define BUF_ALIGN (4096UL)

#define WRITE0_SIZE (512UL)
#define WRITE1_SIZE (4096UL)

#define msg_exit(ret, args...) do { \
	printf(args); exit(ret); } while (0)

int main(int argc, char *argv[]) {
	io_context_t ioctx = 0;
	struct io_event events[2];
	struct iocb *iocbs[2];
	char *filename = argv[1];
	char *bufs[2];
	int fd;

	if (argc != 2)
		msg_exit(EXIT_FAILURE, "Usage: %s <filename>\n", argv[0]);

	unlink(filename); // just kill it
	if ((fd = open(filename, O_RDWR|O_CREAT|O_EXCL|O_SYNC, 0660)) == -1)
		msg_exit(EXIT_FAILURE, "Error creating file %s: %m\n", filename);
	ftruncate(fd, WRITE0_SIZE);
	close(fd);

	posix_memalign((void **)&bufs[0], BUF_ALIGN, WRITE0_SIZE);
	memset(bufs[0], '0', WRITE0_SIZE);
	posix_memalign((void **)&bufs[1], BUF_ALIGN, WRITE1_SIZE);
	memset(bufs[1], '1', WRITE1_SIZE);

	iocbs[0] = malloc(sizeof(struct iocb));
	iocbs[1] = malloc(sizeof(struct iocb));

	fd = open(filename, O_RDWR|O_DIRECT);
	io_prep_pwrite(iocbs[0], fd, bufs[0], WRITE0_SIZE, 0);
	io_prep_pwrite(iocbs[1], fd, bufs[1], WRITE1_SIZE, WRITE0_SIZE);

	if (io_setup(2, &ioctx) != 0)
		msg_exit(EXIT_FAILURE, "Error with io_setup: %m\n");

	io_submit(ioctx, 2, iocbs);
	io_getevents(ioctx, 2, 2, events, NULL);

	io_destroy(ioctx);
	fsync(fd);

	pread(fd, bufs[0], WRITE0_SIZE, 0);
	pread(fd, bufs[1], WRITE1_SIZE, WRITE0_SIZE);

	/* all buffers should be nonzero */
	if ((memchr(bufs[0], 0x00, WRITE0_SIZE) != 0) ||
	    (memchr(bufs[1], 0x00, WRITE1_SIZE) != 0))
		msg_exit(EXIT_FAILURE, "FAILURE\n");
	msg_exit(EXIT_SUCCESS, "SUCCESS\n");
}
