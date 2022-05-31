/*
	test program for unaligned O_DIRECT aio writes on EXT4

	Frank Sorenson - <sorenson@redhat.com>
	2019

	requires libaio, ext4 filesystem


		# gcc aio_repro.c -o aio_repro -laio

	in a directory on ext4:

		# ./aio_repro testfile [ *<trunc_size> | <write_size>[@pos] ][,[ *<trunc_size> | <write_size>]]



	writes given on the command line will generate an IO
	truncate sizes given will truncate the file to that size, at that particular point in the series


	for example:
		# ./aio_repro testfile *5120,512,512,4096,4096,512,1024
		* TRUNCATE to 5120
		0: 512 at 0
		1: 512 at 512
		2: 4096 at 1024
		3: 4096 at 5120
		4: 512 at 9216
		5: 1024 at 9728


	write sizes and positions must be aligned to the minimum IO size for the device (usually 512 bytes)



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
#include <sys/statvfs.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <libgen.h>
#include <sys/sysmacros.h>


#define BUF_ALIGN (1024UL)

#ifndef BLKPBSZGET
#define BLKSSZGET  _IO(0x12,104) /* get block device sector size */
#endif

#define unlikely(x)     __builtin_expect((x),0)
#define MAX_ERRNO       4095
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline unsigned long ERR_PTR(long error) {
        return (unsigned long) error;
}
static inline long PTR_ERR(unsigned long ptr) {
        return (long) ptr;
}
static inline long IS_ERR(unsigned long ptr) {
        return IS_ERR_VALUE((unsigned long)ptr);
}
static inline long IS_ERR_OR_NULL(unsigned long ptr) {
        return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

struct test_write {
	unsigned long pos;
	unsigned long size;
	unsigned long trunc_size;
	int submit_ios;
	struct iocb iocb;
	char *buf;
};

struct test_info {
	struct test_write *writes;
	int write_count;
	long block_size;
	char *dir_path;
	char *path;
	int loop_count;
	io_context_t io_ctx;
	struct io_event *events;
	struct iocb **iocbs;
	int verbose;
};
//struct test_info *test_info;


#define ARRAY_LENGTH(a) (sizeof(a) / sizeof(a[0]))
#define IN_PAGE(x) ((x + 4095) / 4096)

#define msg_exit(ret, args...) do { \
	printf("%s@%s:%d: ", __func__, __FILE__, __LINE__); \
	printf(args); exit(ret); } while (0)

#if 0
struct io_context {
	char refcount_dummy[8];
        int active_ref;
        int nr_tasks;

	char lock_dummy[4];
        unsigned short ioprio;

        int nr_batch_requests;     /* Number of requests left in the batch */
        unsigned long last_waited; /* Time last woken after wait for request */

	char radix_tree_root_dummy[16];
	char io_cq_dummy[56];
	char icq_list_dummy[8];
	char release_work_dummy[32];
};
void dump_io_context(struct io_context *ioc) {
	printf("(struct io_context *)%p {\n", ioc);
	printf("    atomic_long_t refcount\n");
	printf("    atomic_t native_ref = %d\n", ioc->active_ref);
	printf("    atomic_t nr_tasks = %d\n", ioc->nr_tasks);
	printf("    spinlock_t lock\n");
	printf("    unsigned short ioprio = %d\n", ioc->ioprio);
	printf("    int nr_batch_requests = %d\n", ioc->nr_batch_requests);
	printf("    unsigned long last_waited = %lu\n", ioc->last_waited);
	printf("    radix_tree root icq_tree\n");
	printf("    struct io_cq *icq_hint\n");
	printf("    struct list_head icq_list\n");
	printf("    struct radix_tree_root icq_tree\n");
	printf("    struct work_struct release_work\n");
	printf("};\n");
}
#endif

int parse_sizes(struct test_info *test_info, int argc, char *argv[]) {
	char *size_str;
	char *pbuf, *p, *pend;
	int i = 0;

	pbuf = size_str = strdup(argv[3]);
	pend = size_str + strlen(size_str);

	while ((p = strsep(&pbuf, ","))) {
		if ((strtoul(p,  NULL, 10)))
			test_info->write_count++;
	}
	test_info->writes = calloc(sizeof(struct test_write), test_info->write_count);

	p = size_str;
	while (p < pend) {
		if (*p == '*') { /* truncate size */
			unsigned long current = strtoul(p + 1, NULL, 10);

			test_info->writes[i].trunc_size = current;
		} else {
			char *endptr;

			test_info->writes[i].size = strtoul(p, &endptr, 10);
			if (test_info->writes[i].size) {
//				if (test_info->writes[i].size % test_info->block_size)
//					msg_exit(EXIT_FAILURE, "ERROR: write size '%lu' is not a multiple of the block size '%ld'\n",
//						test_info->writes[i].size, test_info->block_size);

				if (*endptr == '@') {
					test_info->writes[i].pos = strtoul(endptr + 1, NULL, 10);
					if (test_info->writes[i].pos % test_info->block_size)
						msg_exit(EXIT_FAILURE, "ERROR: write position '%lu' is not a multiple of the block size '%ld'\n",
							test_info->writes[i].pos, test_info->block_size);
				} else if (*endptr == '\0') {
					if (i == 0)
						test_info->writes[i].pos = 0;
					else
						test_info->writes[i].pos = test_info->writes[i - 1].pos + test_info->writes[i - 1].size;
				} else
					msg_exit(EXIT_FAILURE, "ERROR: unexpected characters in string: '%s'\n", endptr);

				posix_memalign((void **)&test_info->writes[i].buf, BUF_ALIGN, test_info->writes[i].size);
				memset(test_info->writes[i].buf, '0' + i, test_info->writes[i].size);

				i++;
			}
		}
		p += strlen(p) + 1;
	}
	free(size_str);

	printf("found %d sizes:\n", test_info->write_count);
	for (i = 0 ; i < test_info->write_count ; i++) {
		if (test_info->writes[i].trunc_size)
			printf("\t* TRUNCATE to %lu (0x%lx)\n", test_info->writes[i].trunc_size, test_info->writes[i].trunc_size);
		printf("\t%d: %lu at %lu\n", i, test_info->writes[i].size, test_info->writes[i].pos);

//           printf("%2$*1$d", width, num);

	}
	return test_info->write_count;
}
int file_exists(const char *path) {
	struct stat st;

	return stat(path, &st) == 0;
}


void get_blocksize(struct test_info *test_info) {
	char *syspath;
	struct stat st;
	char buf[32];
	int fd;

	stat(test_info->dir_path, &st);

	/* would be nice to BLKSSZGET, but can't be done as non-root, and would require determining the block device path under /dev... this is just easier */
	/* potential sysfs files: hw_sector_size logical_block_size minimum_io_size physical_block_size */
	asprintf(&syspath, "/sys/dev/block/%d:%d/queue/minimum_io_size", major(st.st_dev), minor(st.st_dev));
	if (!file_exists(syspath)) {
		if (errno == ENOENT) { /* try again with a slighly different path */
			free(syspath);
			asprintf(&syspath, "/sys/dev/block/%d:%d/../queue/minimum_io_size", major(st.st_dev), minor(st.st_dev));
			if (!file_exists(syspath)) {
				printf("couldn't determine minimum_io_size for device %d:%d: %m\n", major(st.st_dev), minor(st.st_dev));
				exit(EXIT_FAILURE);
			}
		} else {
			printf("couldn't determine minimum_io_size for device %d:%d: %m\n", major(st.st_dev), minor(st.st_dev));
			exit(EXIT_FAILURE);
		}
	}


	if ((fd = open(syspath, O_RDONLY)) < 0)
		msg_exit(EXIT_FAILURE, "ERROR: could not open device path '%s' to determine blocksize for '%s': %m\n",
			syspath, test_info->dir_path);
	if (read(fd, buf, sizeof(buf)) <= 0)
		msg_exit(EXIT_FAILURE, "ERROR: could not read from '%s': %m\n", syspath);

	test_info->block_size = strtol(buf, NULL, 10);
	if (test_info->block_size <= 0)
		test_info->block_size = 1;

	free(syspath);
	close(fd);
}
void get_path(struct test_info *test_info, const char *path) {
	char *tmp_path;

	tmp_path = strdup(path);
	if ((test_info->dir_path = canonicalize_file_name(dirname(tmp_path))) == 0)
		msg_exit(EXIT_FAILURE, "ERROR: could not canonicalize parent directory of '%s': %m\n",
			tmp_path);
	test_info->path = strdup(basename(tmp_path));

//	printf("dirname(%s): %s\n", tmp_path, test_info->dir_path);
//	printf("basename(%s): %s\n", tmp_path, test_info->path);

	free(tmp_path);
}

int do_one_test(struct test_info *test_info) {
	int fd, ret = EXIT_FAILURE;
	int i;

	if ((fd = open(test_info->path, O_RDWR|O_CREAT|O_TRUNC|O_DIRECT, 0660)) == -1)
		msg_exit(2, "Error creating file %s errno=%d %m\n", test_info->path, errno);


	test_info->io_ctx = 0;
	if ((ret = io_setup(test_info->write_count, &test_info->io_ctx)) != 0)
		msg_exit(EXIT_FAILURE, "Error with io_setup: %m\n");



	for (i = 0 ; i < test_info->write_count ; i++) {
		test_info->iocbs[i] = &test_info->writes[i].iocb;
		io_prep_pwrite(test_info->iocbs[i], fd, test_info->writes[i].buf, test_info->writes[i].size, test_info->writes[i].pos);
	}

	for (i = 0 ; i < test_info->write_count ; i++) {
//		io_prep_pwrite(test_info->iocbs[i], fd, bufs[i], write_sizes[i], write_positions[i]);
//		io_submit(test_info->io_ctx, 1, &test_info->iocbs[i]);
//		io_submit(test_info->io_ctx, 1, test_info->writes[i].iocb);

		if (test_info->writes[i].trunc_size)
			ftruncate(fd, test_info->writes[i].trunc_size);

		io_submit(test_info->io_ctx, 1, &test_info->iocbs[i]);
//		printf("submitted io %d\n", i);
	}

/* ********** */
	ret = io_getevents(test_info->io_ctx, test_info->write_count, test_info->write_count, test_info->events, NULL);

	if (test_info->verbose)
		printf("received %d events\n", ret);
	io_destroy(test_info->io_ctx);
	fsync(fd);
	close(fd);

	ret = EXIT_SUCCESS;
	fd = open(test_info->path, O_RDONLY);
	for (i = 0 ; i < test_info->write_count ; i++) {
		int j;

		for (j = 0 ; j < test_info->write_count ; j++) {
			if (test_info->iocbs[i] == test_info->events[j].obj) {
				if (test_info->verbose)
					printf(" io %d (returned as event %d): %lu bytes at %lu: (0x%lx-0x%lx) ",
						i, j, test_info->writes[i].size, test_info->writes[i].pos,
						test_info->writes[i].pos, test_info->writes[i].pos + test_info->writes[i].size - 1);
				if (test_info->writes[i].size == test_info->events[j].res) {
					if (pread(fd, test_info->writes[i].buf, test_info->writes[i].size, test_info->writes[i].pos) != test_info->writes[i].size) {
						printf("FAILURE\n");
						ret = EXIT_FAILURE;
						continue;
					}
					if (memchr(test_info->writes[i].buf, 0x00, test_info->writes[i].size) != 0) {
						printf("FAILURE\n");
						ret = EXIT_FAILURE;
						continue;
					}

					printf("SUCCESS\n");
				} else if (IS_ERR(test_info->events[j].res)) {
					int res = 0 - PTR_ERR(test_info->events[j].res);
					printf("FAILURE (%d: %s)\n", res, strerror(res));
					ret = EXIT_FAILURE;
					continue;
				} else {
					printf("FAILURE (got %lu bytes)\n", test_info->events[j].res);
					ret = EXIT_FAILURE;
					continue;
				}
			}
		}
	}
	return ret;
}



int main(int argc, char *argv[]) {
//	unsigned long sleep_time = 0;
//	unsigned long *write_positions;

	struct test_info test_info;
	int ret;
	int i;

	if (argc != 4)
		msg_exit(1, "Usage: %s <loop_count> <filename> <size>[,<size>[,<size>]]\n", argv[0]);

	memset(&test_info, 0, sizeof(struct test_info));

	test_info.verbose = 1;
	test_info.loop_count = strtol(argv[1], NULL, 10);
	test_info.path = argv[2];

	get_path(&test_info, test_info.path);
	get_blocksize(&test_info);

	if (parse_sizes(&test_info, argc, argv) < 1)
		msg_exit(EXIT_FAILURE, "ERROR: 0 valid write sizes found\nUsage: %s <filename> <size>[,<size>[,<size>]]\n", argv[0]);


	test_info.events = calloc(sizeof(struct io_event), test_info.write_count);
	test_info.iocbs = malloc(sizeof(struct iocb *) * test_info.write_count);

	for (i = 0 ; i < test_info.loop_count ; i++) {
		if ((ret = do_one_test(&test_info)) == EXIT_FAILURE)
			break;
	}


	if (ret == EXIT_SUCCESS)
		msg_exit(EXIT_SUCCESS, "SUCCESS\n");
	else
		msg_exit(EXIT_FAILURE, "FAILURE\n");


#if 0
	if ((fd = open(test_info.path, O_RDWR|O_CREAT|O_TRUNC|O_DIRECT, 0660)) == -1)
		msg_exit(2, "Error creating file %s errno=%d %m\n", test_info.path, errno);



	for (i = 0 ; i < test_info.write_count ; i++) {
		test_info.iocbs[i] = &test_info.writes[i].iocb;
		io_prep_pwrite(test_info.iocbs[i], fd, test_info.writes[i].buf, test_info.writes[i].size, test_info.writes[i].pos);
	}

	for (i = 0 ; i < test_info.write_count ; i++) {
//		io_prep_pwrite(test_info.iocbs[i], fd, bufs[i], write_sizes[i], write_positions[i]);
//		io_submit(io_ctx, 1, &test_info.iocbs[i]);
//		io_submit(io_ctx, 1, test_info.writes[i].iocb);

		if (test_info.writes[i].trunc_size)
			ftruncate(fd, test_info.writes[i].trunc_size);

		io_submit(io_ctx, 1, &test_info.iocbs[i]);
//		printf("submitted io %d\n", i);
	}
#endif

/* ********** */
#if 0
	ret = io_getevents(io_ctx, test_info.write_count, test_info.write_count, events, NULL);

	printf("received %d events\n", ret);
	io_destroy(io_ctx);
	fsync(fd);
	close(fd);

	ret = EXIT_SUCCESS;
	fd = open(test_info.path, O_RDONLY);
	for (i = 0 ; i < test_info.write_count ; i++) {
		int j;

		for (j = 0 ; j < test_info.write_count ; j++) {
			if (test_info.iocbs[i] == events[j].obj) {
				printf(" io %d (returned as event %d): %lu bytes at %lu: (0x%lx-0x%lx) ",
					i, j, test_info.writes[i].size, test_info.writes[i].pos,
					test_info.writes[i].pos, test_info.writes[i].pos + test_info.writes[i].size - 1);
				if (test_info.writes[i].size == events[j].res) {
					if (pread(fd, test_info.writes[i].buf, test_info.writes[i].size, test_info.writes[i].pos) != test_info.writes[i].size) {
						printf("FAILURE\n");
						ret = EXIT_FAILURE;
						continue;
					}
					if (memchr(test_info.writes[i].buf, 0x00, test_info.writes[i].size) != 0) {
						printf("FAILURE\n");
						ret = EXIT_FAILURE;
						continue;
					}

					printf("SUCCESS\n");
				} else if (IS_ERR(events[j].res)) {
					int res = 0 - PTR_ERR(events[j].res);
					printf("FAILURE (%d: %s)\n", res, strerror(res));
					ret = EXIT_FAILURE;
					continue;
				} else {
					printf("FAILURE (got %lu bytes)\n", events[j].res);
					ret = EXIT_FAILURE;
					continue;
				}
			}
		}
	}

	if (ret == EXIT_SUCCESS)
		msg_exit(EXIT_SUCCESS, "SUCCESS\n");
	else
		msg_exit(EXIT_FAILURE, "FAILURE\n");
#endif
}

#if 0
/* example output */

# while /var/tmp/aio_repro testfile *5120,512,512,4096,512,4096 ; do : ; done
found 5 sizes:
	* TRUNCATE to 5120
	0: 512 at 0
	1: 512 at 512
	2: 4096 at 1024
	3: 512 at 5120
	4: 4096 at 5632
received 5 events
 io 0 (returned as event 0): 512 bytes at 0: SUCCESS
 io 1 (returned as event 1): 512 bytes at 512: SUCCESS
 io 2 (returned as event 3): 4096 bytes at 1024: FAILURE
 io 3 (returned as event 2): 512 bytes at 5120: SUCCESS
 io 4 (returned as event 4): 4096 bytes at 5632: SUCCESS
main@/var/tmp/zzz.c:339: FAILURE
[root@vm7 tmp]# hexdump -C testfile
00000000  30 30 30 30 30 30 30 30  30 30 30 30 30 30 30 30  |0000000000000000|
*
00000200  31 31 31 31 31 31 31 31  31 31 31 31 31 31 31 31  |1111111111111111|
*
00000400  32 32 32 32 32 32 32 32  32 32 32 32 32 32 32 32  |2222222222222222|
*
00001000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00001400  33 33 33 33 33 33 33 33  33 33 33 33 33 33 33 33  |3333333333333333|
*
00001600  34 34 34 34 34 34 34 34  34 34 34 34 34 34 34 34  |4444444444444444|
*
00002600
#endif

