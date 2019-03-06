/*
	test program for unaligned O_DIRECT aio writes on EXT4

	Frank Sorenson - <sorenson@redhat.com>
	2019

	requires libaio, ext4 filesystem


		# gcc aio_repro.c -o aio_repro -laio

	in a directory on ext4:

		# ./aio_repro testfile

	or introduce a 10 millisecond delay between writes:

		# ./aio_repro testfile 10000

	(delay is expressed in microseconds)


	the test file can also be checked with hexdump:

# hexdump -C testfile
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
03d00200  30 30 30 30 30 30 30 30  30 30 30 30 30 30 30 30  |0000000000000000|
*
03e00200  31 31 31 31 31 31 31 31  31 31 31 31 31 31 31 31  |1111111111111111|
*
03f00200  32 32 32 32 32 32 32 32  32 32 32 32 32 32 32 32  |2222222222222222|
*
04000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
04000200  33 33 33 33 33 33 33 33  33 33 33 33 33 33 33 33  |3333333333333333|
*
04100200


*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <libaio.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

#define BUF_ALIGN 1024
#define BUF_SIZE  (1048576)

#define NUM_BUFS (2)
#define NUM_EVENTS (10)
#define NUM_IOCBS (4)

#define WRITE0_POS (15616 * 4096 + 512)
#define TRUNCATE_SIZE (WRITE0_POS + BUF_SIZE)
#define TEST_POS (WRITE0_POS + BUF_SIZE - 512)

#define msg_exit(ret, args...) do { \
	printf("%s@%s:%d: ", __func__, __FILE__, __LINE__); \
	printf(args); exit(ret); } while (0)

int check_nonzero(const char *filename, off_t offset, size_t count) {
	char *buf, *cmp_buf;
	int ret;
	int fd;

	buf = malloc(count);
	cmp_buf = malloc(count);
	memset(cmp_buf, 0, count);

	fd = open(filename, O_RDONLY);
	lseek(fd, offset, SEEK_SET);
	read(fd, buf, count);
	close(fd);

	ret = memcmp(buf, cmp_buf, count);

	free(cmp_buf);
	free(buf);
	return ret != 0;
}

int main(int argc, char *argv[]) {
	unsigned int sleep_time = 0;
	io_context_t io_ctx = 0;
	struct io_event *events;
	struct iocb **iocbs;
	char *buf[NUM_BUFS];
	char *filename;
	int fd, ret;
	int i;

	if (argc == 3)
		sleep_time = strtoul(argv[2], NULL, 10);
	else if (argc != 2)
		msg_exit(1, "Usage: %s <filename> [<MICROSECONDS_DELAY>]\n", argv[0]);

	filename = argv[1];

	events = malloc(sizeof(struct io_event) * NUM_EVENTS);
	memset(events, 0, sizeof(struct io_event) * NUM_EVENTS);

	iocbs = malloc(sizeof(struct iocb *) * NUM_IOCBS);
	for (i = 0 ; i < NUM_IOCBS ; i++)
		iocbs[i] = malloc(sizeof(struct iocb));

	for (i = 0 ; i < NUM_BUFS ; i++) {
		posix_memalign((void **)&buf[i], BUF_ALIGN, BUF_SIZE);
		memset(buf[i], '0' + i, BUF_SIZE);
	}


	unlink(filename); // just kill it

	if ((fd = open(filename, O_RDWR|O_CREAT|O_EXCL|O_SYNC, 0660)) == -1)
		msg_exit(2, "Error creating file %s errno=%d %m\n", filename, errno);
	ftruncate(fd, TRUNCATE_SIZE);
	close(fd);

	fd = open(filename, O_RDWR|O_DIRECT);

	if ((ret = io_setup(1, &io_ctx)) != 0)
		msg_exit(3, "Error with io_setup: %m\n");

	for (i = 0 ; i < NUM_BUFS ; i++) {
		io_prep_pwrite(iocbs[i], fd, buf[i], BUF_SIZE, WRITE0_POS + (i * BUF_SIZE));
		io_submit(io_ctx, 1, &iocbs[i]);
		printf("submitted io %d\n", i);
		if (sleep_time)
			usleep(sleep_time);
	}

	ret = io_getevents(io_ctx, NUM_BUFS, NUM_BUFS, events, NULL);
	printf("received %d events\n", ret);

	io_destroy(io_ctx);
	fsync(fd);
	close(fd);

	for (i = 0 ; i < NUM_BUFS ; i++)
		free(buf[i]);

	for (i = 0 ; i < NUM_IOCBS ; i++)
		free(iocbs[i]);
	free(iocbs);
	free(events);

	if (check_nonzero(filename, TEST_POS, 512)) {
		printf("success\n");
		ret = EXIT_SUCCESS;
	} else {
		printf("512 bytes at %d were null\n", TEST_POS);
		ret = EXIT_FAILURE;
	}

	return ret;
}
