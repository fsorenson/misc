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

#define BUF_SIZE 1024

static char filler_bytes[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890";

#define do_write(child_id, i, fd, buf, pos, size) do { \
	struct stat st; \
	off_t current_pos; \
	memset(buf, filler_bytes[i % sizeof(filler_bytes)], size); \
	pwrite(fd, buf, size, pos); \
	fstat(fd, &st); \
	current_pos = lseek(fd, 0, SEEK_CUR); \
	printf("%d: child %d - after %d-byte write(fd=%d) at %d, size is %ld, file position = %ld\n", \
		++i, child_id, size, fd, pos, st.st_size, current_pos); \
} while (0)


char *path;
struct child_struct {
	pthread_t t;
	int id;
};

void *child_work(void *arg) {
	struct child_struct *me = arg;
        int child_id = me->id;
	int count = 0;
	char *buf;
	int fd;
	int i;


	posix_memalign((void **)&buf, BUF_SIZE, BUF_SIZE);

	fd = open(path, O_RDWR|O_CREAT|O_APPEND|O_DIRECT);

	for (i = 0 ; i < 100 ; i++) {
		do_write(child_id, count, fd, buf, BUF_SIZE * 3, BUF_SIZE);

	}

/*
	do_write(count, fd1, buf, BUF_SIZE * 4, BUF_SIZE);
	do_write(count, fd2, buf, BUF_SIZE * 1, BUF_SIZE);
	do_write(count, fd1, buf, BUF_SIZE * 0, BUF_SIZE);
	do_write(count, fd2, buf, BUF_SIZE * 3, BUF_SIZE);
	do_write(count, fd1, buf, BUF_SIZE * 1, BUF_SIZE);
	do_write(count, fd2, buf, BUF_SIZE * 1, BUF_SIZE);
	do_write(count, fd1, buf, BUF_SIZE * 0, BUF_SIZE);
	do_write(count, fd2, buf, BUF_SIZE * 57, BUF_SIZE);

	do_write(count, fd1, buf, BUF_SIZE * 5, BUF_SIZE);

*/

	close(fd);

	return NULL;
}


int main(int argc, char *argv[]) {
	struct child_struct children[2];
	pthread_attr_t attr;
	int fd;

	if (argc != 2) {
		printf("Usage: %s /path/to/file\n", argv[0]);
		return EXIT_FAILURE;
	}

	path = argv[1];

	pthread_attr_init(&attr);
	pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setstacksize(&attr, (size_t) (1 * 1024 * 1024));

	children[0].id = 0;
	children[1].id = 1;

	fd = open(path, O_RDWR|O_CREAT|O_TRUNC|O_DIRECT, 0600);
	close(fd);


	pthread_create(&children[0].t, &attr, child_work, (void *) &children[0]);
	pthread_create(&children[1].t, &attr, child_work, (void *) &children[1]);


	pthread_join(children[0].t, NULL);
	pthread_join(children[1].t, NULL);

	return EXIT_FAILURE;
}
