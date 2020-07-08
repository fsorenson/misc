/*
	program to replicate bug that results in negative disk
	space reported on xfs filesystem

	Frank Sorenson <sorenson@redhat.com>, 2018

	# gcc iometer_repl-1.c -o iometer_repl-1 -laio -lpthread

	# ./iometer_repl-1 /path/to/testfile
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <libaio.h>
#include <pthread.h>
#include <sys/vfs.h>

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)

#define MSinNS (1000000ULL)
#define USinNS (1000ULL)

#define NUM_THREADS 8

#define WRITE_SIZE (64ULL * KiB)
#define FILE_SIZE (5ULL * GiB)

#define IOCB_NUM 512
#define MAX_EVENTS 512

#define TRACING_ANNOTATE 1

#define mb()	__asm__ __volatile__("mfence" ::: "memory")
#define nop()	__asm__ __volatile__ ("nop")

static char filler_bytes[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890";

struct per_thread_info {
	int child_id;
	pthread_t tid;
};

struct shared_data_struct {
	char *path;
	int parent_fd;
	volatile bool replicated;
	struct per_thread_info threads[NUM_THREADS];
	int live_threads;

} *shared_data;

#if TRACING_ANNOTATE

#define TRACING_ANNOTATE_FILE "/sys/kernel/debug/tracing/trace_marker"
#define write_file_string(_file, _buf) do { \
	int fd; \
	if ((fd = open(_file, O_WRONLY | O_SYNC)) >= 0) { \
		write(fd, _buf, strlen(_buf)); \
		close(fd); \
	} \
} while (0)

#define trace_printf(args...) do { \
	char *buf; \
	asprintf(&buf, args); \
	write_file_string(TRACING_ANNOTATE_FILE, buf); \
	free(buf); \
} while (0)

#else

#define tracing_printf(args...) do { } while (0)

#endif

void child_work(int child_id) {
	int cancel_low, cancel_high;
	off_t pos = 0;
	char *buf;
	int ret;
	int fd;
	int i;

	io_context_t io_ctx;
	struct io_event *events;
	struct iocb **iocbs;
	struct timespec timeout = { .tv_sec = 600, .tv_nsec = 0ULL };

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

	posix_memalign((void **)&buf, WRITE_SIZE, WRITE_SIZE);
	memset(buf, filler_bytes[child_id % sizeof(filler_bytes)], WRITE_SIZE);

	if ((fd = open(shared_data->path, O_RDWR|O_CREAT|O_APPEND|O_DIRECT)) < 0) {
		printf("child %d could not open testfile '%s': %m\n", child_id, shared_data->path);
		goto out_free;
	}
	while (pos < FILE_SIZE) {
		mb();
		if (shared_data->replicated)
			break;
		for (i = 0 ; i < IOCB_NUM ; i++) {
			io_prep_pwrite(iocbs[i], fd, buf, WRITE_SIZE, pos);
			if ((ret = io_submit(io_ctx, 1, &iocbs[i])) < 0) {
				printf("io_submit() returned error: %m\n");
				cancel_low = 0;
				cancel_high = i - 1;
				goto out_cancel;
			}
			pos += WRITE_SIZE;
		}

		for (i = 0 ; i < IOCB_NUM ; i++) {
wait_again:
			mb();
			if (shared_data->replicated) {

				trace_printf("child %d exiting\n", child_id);
				cancel_low = i;
				cancel_high = IOCB_NUM;
				goto out_cancel;
			}

			if ((ret = io_getevents(io_ctx, 1, 1, &events[i], &timeout)) == 0)
				goto wait_again;
			else if (ret == -EINTR)
				goto wait_again;
			else if (ret < 0) {
				printf("io_getevents() returned error: %d (%s)\n", -ret, strerror(-ret));
				cancel_low = i + 1;
				cancel_high = IOCB_NUM;
				goto out_cancel;
			} else {
				if ((long)events[i].res < 0) {
					printf("error: %s\n", strerror(-events[i].res));
					goto out;
				}
			}
		}
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

out_exit:
	pthread_exit(0);
}

void check_child_exit(void) {
	int i;

	for (i = 0 ; i < NUM_THREADS ; i++) {
		if (shared_data->threads[i].tid) {
			if ((pthread_tryjoin_np(shared_data->threads[i].tid, NULL)) == 0) {
				shared_data->threads[i].tid = 0;
				shared_data->live_threads--;
			}
		}
	}
}

static bool check_statvfs(const char *path) {
	struct statvfs st;
	statvfs(path, &st);
	return (st.f_bfree > st.f_blocks);
}
static bool check_fstatvfs(const int fd) {
	struct statvfs st;
	fstatvfs(fd, &st);
	return (st.f_bfree > st.f_blocks);
}
void parent_wait(void) {
//	struct timespec ts = { .tv_sec = 0, .tv_nsec = 500ULL*MSinNS };
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100ULL };
//	struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
	int i;

	while ((shared_data->live_threads > 0) && (!shared_data->replicated)) {
		nanosleep(&ts, NULL);

//		if (check_statvfs(shared_data->path) || check_fstatvfs(shared_data->parent_fd))
		if (check_fstatvfs(shared_data->parent_fd)) {
			shared_data->replicated = true;
			mb();
			trace_printf("parent process detected repro was successful\n");
			break;
		}
		check_child_exit();
		mb();
	}
	for (i = NUM_THREADS ; i < NUM_THREADS ; i++)
		pthread_cancel(shared_data->threads[i].tid);
	while (shared_data->live_threads > 0) {
		nanosleep(&ts, NULL);
		check_child_exit();
	}
}

void *start_work_thread(void *arg) {
	struct per_thread_info *tid = (struct per_thread_info *)arg;
	int child_id = tid->child_id;

	child_work(child_id);
	return 0;
}

void start_threads(void) {
	pthread_attr_t attr;
	int i;

	pthread_attr_init(&attr);
	pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setstacksize(&attr, (size_t) (1 * 1024 * 1024));

	for (i = 0 ; i < NUM_THREADS ; i++) {
		shared_data->threads[i].child_id = i;

		if (pthread_create(&shared_data->threads[i].tid, &attr, start_work_thread, (void *) &shared_data->threads[i]) != 0) {
/* maybe do something... */
		} else
			shared_data->live_threads++;
	}
}

int main(int argc, char *argv[]) {
	int iter = 0;

	shared_data = mmap(NULL, sizeof(struct shared_data_struct), PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_ANONYMOUS, -1, 0);

	if (argc != 2) {
		printf("Usage: %s /path/to/file\n", argv[0]);
		return EXIT_FAILURE;
	}

	shared_data->path = argv[1];
	shared_data->replicated = false;

	while (! shared_data->replicated) {
		shared_data->live_threads = 0;
		if ((shared_data->parent_fd = open(shared_data->path, O_RDWR|O_CREAT|O_TRUNC|O_DIRECT, 0600)) < 0) {
			printf("error opening testfile '%s': %m\n", shared_data->path);
			break;
		}

		printf("iteration %d\n", ++iter);

		start_threads();

		parent_wait();
		close(shared_data->parent_fd);
	}
	printf("replicated: %s\n", shared_data->replicated ? "TRUE" : "FALSE");

	return (shared_data->replicated ? EXIT_SUCCESS : EXIT_FAILURE);
}
