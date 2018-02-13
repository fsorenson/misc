#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/time.h>

#define KiB (1024ULL)
#define MiB (KiB * KiB)

#define BUF_SIZE (8ULL * KiB)
#define FILE_SIZE (8ULL * MiB)

#define CHILD_USLEEP (750000)

#define THREADS 5
#define MONITOR_INTERVAL_SEC (1)
#define MONITOR_INTERVAL_USEC (000000ULL)

#define BASE_STRING "test_direct"

struct state {
	pid_t child_pids[THREADS];

	unsigned long long counter[THREADS];
	unsigned long long last_count[THREADS];
	struct timespec last_time;
};
struct state *test_state;

void child_work(char *base_path, int child_id) {
	off_t pos = 0;
	char *path;
	char *buf;
	int ret;
	int fd;

	posix_memalign((void **)&buf, BUF_SIZE, BUF_SIZE);
	memset(buf, 0x55, BUF_SIZE);

	asprintf(&path, "%s/%s.%d", base_path, BASE_STRING, child_id);

	if ((fd = open(path, O_CREAT|O_TRUNC|O_RDWR|O_DIRECT, 0644)) < 0) {
		printf("error opening file 'path': %m\n");
		return;
	}

	while (42) { /* while (1) is boring */
//		ftruncate(fd, pos + BUF_SIZE);
		if ((ret = pwrite(fd, buf, BUF_SIZE, pos)) < 0) {
			printf("pwrite() failed: %m\n");
		}
		pos = (pos + BUF_SIZE) % FILE_SIZE;

		test_state->counter[child_id]++;
		usleep(CHILD_USLEEP + child_id * 1000); /* stagger threads with a little variety */
	}
}

void show_stats(int sig) {
	unsigned long long current_counts[THREADS];
	int ret;

	memcpy(current_counts, test_state->counter, (sizeof current_counts[0]) * THREADS);
	ret = memcmp(current_counts, test_state->last_count, (sizeof current_counts[0]) * THREADS);
	if (ret)
		printf(".");
	else
		printf("X");
	fflush(stdout);
	memcpy(test_state->last_count, current_counts, (sizeof current_counts[0]) * THREADS);
}

void parent_work(void) {
	struct sigaction sa;
	struct itimerval timer;
	sigset_t sig_mask;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &show_stats;
	sigaction(SIGALRM, &sa, NULL);

	timer.it_value.tv_sec = timer.it_interval.tv_sec = MONITOR_INTERVAL_SEC;
	timer.it_value.tv_usec = timer.it_interval.tv_usec = MONITOR_INTERVAL_USEC;
	setitimer(ITIMER_REAL, &timer, 0);

	sigfillset(&sig_mask);
	sigdelset(&sig_mask, SIGCHLD);
	sigdelset(&sig_mask, SIGTERM);
	sigdelset(&sig_mask, SIGINT);
	sigdelset(&sig_mask, SIGALRM);

	while (42)
		sigsuspend(&sig_mask);
}

int main(int argc, char *argv[]) {
	char *base_path;
	pid_t cpid;
	int i;

	if (argc != 2) {
		printf("usage: %s <base_test_path>\n", argv[0]);
		return EXIT_FAILURE;
	}
	base_path = argv[1];

	test_state = mmap(NULL, sizeof(struct state), PROT_READ|PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

	for (i = 0 ; i < THREADS ; i++) {
		if ((cpid = fork()) == 0) {
			test_state->child_pids[i] = cpid;
			child_work(base_path, i);
			return EXIT_FAILURE; /* if we exit an infinite loop, is that a success? */
		}
	}

	parent_work();

	return EXIT_SUCCESS;
}

