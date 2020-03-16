#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define SLEEP_TIME 1

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)

#define BUF_ALIGN (1UL * KiB)
#define IO_SIZE (64ULL * KiB)

#define mb()    __asm__ __volatile__("mfence" ::: "memory")

pid_t gettid(void) {
	return syscall(SYS_gettid);
}

volatile uint64_t *counts;
int *last_count_change;

void open_close_child(int child_id, const char *path) {
	int fd;

	while (42) {
		if ((fd = open(path, O_RDWR)) < 0) {
			printf("child pid %d could not open testfile '%s': %m\n", gettid(), path);
			exit(EXIT_FAILURE);
		}
		close(fd);
		counts[child_id]++;
	}
}
void dio_child(int child_id, const char *path) {
	char *buf = NULL;
	int fd = -1;

	if ((fd = open(path, O_RDONLY|O_DIRECT)) < 0) {
		printf("child pid %d could not open testfile '%s': %m\n", gettid(), path);
		exit(EXIT_FAILURE);
	}

	buf = malloc(IO_SIZE);
	while (42) {
		pread(fd, buf, IO_SIZE, 0);
		counts[child_id]++;
	}
}

int main(int argc, char *argv[]) {
	uint64_t *last_counts = NULL, *current_counts = NULL;
	pid_t *cpids = NULL, cpid;
	int dio_kids, oc_kids;
	int total_children;
	int i, counts_size;
	char *path = NULL;
	int loop_count = 0;

	if (argc != 4) {
		printf("usage: %s <test_file> <dio_threads> <open_close_threads>\n", argv[0]);
		return EXIT_FAILURE;
	}

	path = strdup(argv[1]);
	dio_kids = strtol(argv[2], NULL, 10);
	oc_kids = strtol(argv[3], NULL, 10);

	if (dio_kids < 1) {
		printf("dio child count must be at least %d\n", 1);
		goto out;
	}

	if (oc_kids < 1) {
		printf("open/close child count must be at least %d\n", 1);
		goto out;
	}

	total_children = dio_kids + oc_kids;

	cpids = malloc(total_children * sizeof(pid_t));

	counts_size = total_children * sizeof(uint64_t);
	counts = mmap(NULL, counts_size, PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
	memset((uint64_t *)counts, 0, counts_size);

	for (i = 0 ; i < total_children ; i++) {
		if ((cpid = fork()) == 0) {
			if (i < dio_kids)
				dio_child(i, path);
			else
				open_close_child(i, path);
		} else
			cpids[i] = cpid;
	}

	last_counts = malloc(counts_size);
	current_counts = malloc(counts_size);

	memset(last_counts, 0, counts_size);

	last_count_change = malloc(total_children * sizeof(int));
	memset(last_count_change, 0, total_children * sizeof(int));

	while (42) {
		sleep(SLEEP_TIME);

		mb();
		memcpy(current_counts, (uint64_t *)counts, counts_size);

		loop_count++;
		printf("loop %d (%d seconds)\n", loop_count, loop_count * SLEEP_TIME);
/*
		for (i = 0 ; i < dio_kids ; i++) {
			if (last_counts[i] == current_counts[i])
				printf(" dio child %d (pid %d) stalled at %" PRIu64 " loop(s)\n",
					i, cpids[i], current_counts[i]);
		}
*/
		for (i = dio_kids ; i < total_children ; i++) {
			if (last_counts[i] == current_counts[i])
				printf(" open/close child %d (pid %d) stalled for %d seconds\n",
					i, cpids[i], (loop_count - last_count_change[i]) * SLEEP_TIME);
//at %" PRIu64 " loop(s)\n",
//					i, cpids[i], current_counts[i]);
			else
				last_count_change[i] = loop_count;
		}
		memcpy(last_counts, current_counts, counts_size);
	}

out:
	return EXIT_FAILURE;
}
