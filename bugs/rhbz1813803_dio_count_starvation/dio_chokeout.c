#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <libaio.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <limits.h>
#include <libgen.h>
#include <time.h>
#include <sched.h>

#define BUF_ALIGN (1024UL)
#define POS_ALIGN (512UL)

#ifndef BLKPBSZGET
#define BLKSSZGET  _IO(0x12,104) /* get block device sector size */
#endif

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)

#define MSinNS (1000000ULL)
#define USinNS (1000ULL)
//#define IOCB_NUM 512
//#define IOCB_NUM 32
#define IOCB_NUM 128
#define MAX_EVENTS 512

//#define IO_SIZE (4ULL * KiB)
#define IO_SIZE (64ULL * KiB)
//#define IO_SIZE (1ULL * MiB)
//#define IO_SIZE (1ULL)

#define RAND_STATE_SIZE (256)


#define MIN_AIO_CHILD_COUNT 5
#define MIN_OPEN_CLOSE_CHILD_COUNT 5


#define likely(x)     __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#define mb()    __asm__ __volatile__("mfence" ::: "memory")
#define nop()   __asm__ __volatile__ ("nop")

#define MAX_ERRNO       4095
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

#define ARRAY_LENGTH(a) (sizeof(a) / sizeof(a[0]))
#define IN_PAGE(x) ((x + 4095) / 4096)

#define msg_exit(ret, args...) do { \
	printf("%s@%s:%d: ", __func__, __FILE__, __LINE__); \
	printf(args); exit(ret); } while (0)


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


struct per_thread_info {
	int child_id;
	pid_t child_pid;

	uint64_t count;

//	pthread_t tid;
};


struct test_config {
	struct random_data random_data;
	char *random_statebuf;
	struct per_thread_info *threads;

	int aio_count;
	int open_close_count;

//	struct per_thread_info *children;
	pid_t *pids;
	volatile uint64_t *counts;

	char *path;
} *test_config;

int state_pickanum(struct random_data *random_data, int _low, int _high) { /* both inclusive */
	int low, high;
	int spread;
	int r;

	if (_low < _high) { low = _low ; high = _high; }
	else { low = _high; high = _low; }

	spread = high - low;
	random_r(random_data, &r);
	return (r % (spread + 1)) + low;
}
int pickanum(int _low, int _high) { /* both inclusive */
	return state_pickanum(&test_config->random_data, _low, _high);
}
int thread_pickanum(struct random_data *random_data, int _low, int _high) {
	return state_pickanum(random_data, _low, _high);
}


void open_close_child(int child_id) {
	int fd;

	while (42) {
		if ((fd = open(test_config->path, O_RDWR)) < 0) {
			printf("child %d could not open testfile '%s': %m\n", child_id, test_config->path);
			break;
		}
		sched_yield();
		close(fd);

//		mb();
		test_config->counts[child_id]++;
//		mb();
	}
	exit(EXIT_FAILURE);
}

void aio_child(int child_id) {
	struct timespec timeout = { .tv_sec = 600, .tv_nsec = 0ULL };
	int cancel_low, cancel_high;
	struct io_event *events;
	struct iocb **iocbs;
	io_context_t io_ctx;
	char *buf;
	int ret;

	off_t pos;
	size_t file_size;
	int fd;
	int i;

	struct random_data thread_random_data;
	char *thread_random_statebuf;

	memset(&thread_random_data, 0, sizeof(struct random_data));
	thread_random_statebuf = malloc(RAND_STATE_SIZE);
	memset(thread_random_statebuf, 0, RAND_STATE_SIZE);

	initstate_r(pickanum(0, INT_MAX), thread_random_statebuf, RAND_STATE_SIZE, &thread_random_data);


	memset(&io_ctx, 0, sizeof(io_context_t));
	io_setup(IOCB_NUM, &io_ctx);

        iocbs = malloc(sizeof(struct iocb *) * IOCB_NUM);
        memset(iocbs, 0, IOCB_NUM * sizeof(struct iocb *));

	for (i = 0 ; i < IOCB_NUM ; i++) {
		iocbs[i] = malloc(sizeof(struct iocb));
		memset(iocbs[i], 0, sizeof(struct iocb));
	}

        events = malloc(sizeof(struct io_event) * MAX_EVENTS);
        memset(events, 0, sizeof(struct io_event) * MAX_EVENTS);

//	posix_memalign((void **)&buf, IO_SIZE, IO_SIZE);
	posix_memalign((void **)&buf, POS_ALIGN, IO_SIZE);

	if ((fd = open(test_config->path, O_RDONLY|O_DIRECT)) < 0) {
		printf("child %d could not open testfile '%s': %m\n", child_id, test_config->path);
		goto out_free;
	}

	file_size = lseek(fd, 0, SEEK_END);

	while (42) {
		int this_loop_iocbs = thread_pickanum(&thread_random_data, 1, IOCB_NUM);

//		for (i = 0 ; i < IOCB_NUM ; i++) {
		for (i = 0 ; i < this_loop_iocbs ; i++) {
			pos = thread_pickanum(&thread_random_data, 0, file_size - IO_SIZE);
			/* pos has to be aligned, most likely by 512 bytes */
			pos -= pos % POS_ALIGN;

			io_prep_pread(iocbs[i], fd, buf, IO_SIZE, pos);
                        if ((ret = io_submit(io_ctx, 1, &iocbs[i])) < 0) {
                                printf("io_submit() returned error: %m\n");
                                cancel_low = 0;
                                cancel_high = i - 1;
                                goto out_cancel;
                        }
                }

		for (i = 0 ; i < this_loop_iocbs ; i++) {
wait_again:
			if ((ret = io_getevents(io_ctx, 1, 1, &events[i], &timeout)) == 0)
				goto wait_again;
			else if (ret == -EINTR)
				goto wait_again;
			else if (ret < 0) {
				printf("io_getevents() returned error: %d (%s)\n", -ret, strerror(-ret));
				cancel_low = i + 1;
				cancel_high = this_loop_iocbs;
				goto out_cancel;
			} else {
				if ((long)events[i].res < 0) {
					printf("error: %s\n", strerror(-events[i].res));
					goto out;
				}
			}
		}
//		mb();
//		test_config->counts[child_id]++;
		test_config->counts[child_id] += this_loop_iocbs;
//		mb();
	}
	goto out;

out_cancel:
	for (i = cancel_low ; i < cancel_high ; i++)
		io_cancel(io_ctx, iocbs[i], &events[i]);
out:
	close(fd);

out_free:
	for (i = 0 ; i < IOCB_NUM ; i++)
                free(iocbs[i]);
        free(iocbs);
        free(events);
        free(buf);

        io_destroy(io_ctx);

//out_exit:

//	pthread_exit(0);
	exit(EXIT_FAILURE);
}



int main(int argc, char *argv[]) {
	uint64_t *last_counts, *current_counts;
	int total_children;
	int i, counts_size;
	int iter = 0;

	if (argc != 4) {
		printf("usage: %s <test_file> <aio_threads> <open_close_threads>\n", argv[0]);
		return EXIT_FAILURE;
	}

	test_config = mmap(NULL, sizeof(struct test_config),
		PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	memset(test_config, 0, sizeof(struct test_config));

	test_config->random_statebuf = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE,
		-1, 0);
	memset(test_config->random_statebuf, 0, RAND_STATE_SIZE);
	initstate_r((time(NULL) % INT_MAX),
		test_config->random_statebuf, RAND_STATE_SIZE,
		&test_config->random_data);


	test_config->path = strdup(argv[1]);
	test_config->aio_count = strtol(argv[2], NULL, 10);
	test_config->open_close_count = strtol(argv[3], NULL, 10);

	if (test_config->aio_count < MIN_AIO_CHILD_COUNT) {
		printf("aio child count must be at least %d\n", MIN_AIO_CHILD_COUNT);
		goto out;
	}

	if (test_config->open_close_count < MIN_OPEN_CLOSE_CHILD_COUNT) {
		printf("open/close child count must be at least %d\n", MIN_OPEN_CLOSE_CHILD_COUNT);
		goto out;
	}

	total_children = test_config->aio_count + test_config->open_close_count;

//	test_config->children = malloc((test_config->aio_count + test_config->open_close_count) * sizeof(struct per_thread_info));
	test_config->pids = malloc(total_children * sizeof(pid_t));

	counts_size = total_children * sizeof(uint64_t);

//	test_config->counts = malloc(counts_size);
	test_config->counts = mmap(NULL, counts_size, PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);


	last_counts = malloc(counts_size);
	current_counts = malloc(counts_size);

	for (i = 0 ; i < total_children ; i++) {
		pid_t cpid;

		test_config->counts[i] = 0;
		if ((cpid = fork()) == 0) {
			if (i < test_config->aio_count)
				aio_child(i);
			else
				open_close_child(i);
			goto child_out;
		} else {
			test_config->pids[i] = cpid;
		}
	}

	memset(last_counts, 0, counts_size);

	while (42) {
		sleep(5);

		printf("iteration: %d\n", ++iter);

		mb();
		memcpy(current_counts, (uint64_t *)test_config->counts, counts_size);

		for (i = 0 ; i < test_config->aio_count ; i++) {
			if (last_counts[i] == current_counts[i])
				printf(" aio child %d stalled (%" PRIu64 " vs %" PRIu64 ")\n", i, last_counts[i], current_counts[i]);
		}

		for (i = test_config->aio_count ; i < total_children ; i++) {
			if (last_counts[i] == current_counts[i])
				printf(" open/close child %d stalled (%" PRIu64 " vs %" PRIu64 ")\n", i, last_counts[i], current_counts[i]);
//			else
//				printf(" open/close child %d did %" PRIu64 " loops\n", i, current_counts[i] - last_counts[i]);
		}
		memcpy(last_counts, current_counts, counts_size);
	}

out:
/* should free everything, but... whatever */

child_out:
	return EXIT_FAILURE;
}
