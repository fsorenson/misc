/*
    Frank Sorenson <sorenson@redhat.com>

    test_freezer - reproducer for bug involving freezer cgroup and RPC

    gcc -Wall test_freezer.c -o test_freezer -lrt

*/


#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <sys/time.h>
#include <syslog.h>

#define KiB (1024UL)
#define MiB (KiB * KiB)

#define FREEZER_CGROUP "test_cgroup"
#define CGROUP_BASE "/cgroup/freezer"
#define CGROUP_STATE_FILE CGROUP_BASE "/" FREEZER_CGROUP "/freezer.state"
#define CGROUP_TASK_FILE CGROUP_BASE "/" FREEZER_CGROUP "/tasks"

#define RPC_DEBUG_FILE "/proc/sys/sunrpc/rpc_debug"
#define RPC_DEBUG_VALUE 32767
#define RPC_DEBUG_DISABLE 0

#define CHILD_PROC 5
#define MONITOR_INTERVAL_SEC 0
#define MONITOR_INTERVAL_USEC 250000

enum frozen { THAWED = 0, FROZEN = 1};
struct state {
	pid_t child_pids[CHILD_PROC];
	pid_t parent_pid;

	enum frozen frozen;
	unsigned long count;
	unsigned long last_count;
	struct timespec start_time;
	struct timespec last_time;
};
struct state *test_state;

struct timespec get_time(void) {
        struct timespec ts;

        clock_gettime(CLOCK_REALTIME, &ts);
	return ts;
}

void child_work(char *directory) {
	struct stat st;

	while (1) {
		access(directory, R_OK | W_OK);
		stat(directory, &st);
	}
}

#define write_file_string(_file, _buf) do { \
	int fd; \
	if ((fd = open(_file, O_WRONLY | O_SYNC)) >= 0) { \
		write(fd, _buf, strlen(_buf)); \
		close(fd); \
	} \
} while (0)

#define BUF_LEN_PID_STRING 16
#define write_file_int(_file, _val) do { \
	char buf[BUF_LEN_PID_STRING]; \
	snprintf(buf, BUF_LEN_PID_STRING, "%d", _val); \
	write_file_string(_file, buf); \
} while (0)

#define write_freezer_thawed() do { \
	write_file_string(CGROUP_STATE_FILE, "THAWED"); \
	test_state->frozen = THAWED; \
} while (0)
#define write_freezer_frozen() do { \
	write_file_string(CGROUP_STATE_FILE, "FROZEN"); \
	test_state->frozen = FROZEN; \
} while (0)

void write_pid_file(pid_t pid) {
	char pid_buf[BUF_LEN_PID_STRING];
	int pid_fd;

	snprintf(pid_buf, BUF_LEN_PID_STRING, "%d\n", pid);
	if ((pid_fd = open(CGROUP_TASK_FILE, O_WRONLY)) == -1) {
		printf("Error opening cgroup task file %s: %s\n",
			CGROUP_TASK_FILE, strerror(errno));
		goto err_exit;
	}
	if (write(pid_fd, pid_buf, strlen(pid_buf)) != strlen(pid_buf)) {
		printf("Error writing to cgroup task file %s: %s\n",
			CGROUP_TASK_FILE, strerror(errno));
		goto err_exit;
	}
	close(pid_fd);
	return;
err_exit:
	kill(pid, SIGTERM);
	exit(EXIT_FAILURE);
}

void parent_sig_handler(int sig) {
	int i;

	if (sig == SIGCHLD)
		sig = SIGTERM;
	for (i = 0 ; i < CHILD_PROC ; i ++)
		kill(test_state->child_pids[i], sig);

	exit(EXIT_SUCCESS);
}

void parent_work(char *directory) {
	struct stat st;
	unsigned long i = 0;
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &parent_sig_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGCHLD, &sa, NULL);

	for (i = 0 ; i < CHILD_PROC ; i ++)
		write_pid_file(test_state->child_pids[i]);

	while (1) {
		test_state->count++;
		write_freezer_frozen();
		stat(directory, &st);
		write_freezer_thawed();
	}
}

void start_children(char *directory) {
	int i;
	pid_t cpid;

	for (i = 0 ; i < CHILD_PROC ; i ++) {
		if ((cpid = fork()) == 0)
			child_work(directory);
		test_state->child_pids[i] = cpid;
	}
}

void start_parent(char *directory) {
	pid_t cpid;

	if ((cpid = fork()) != 0)
		parent_work(directory);
	test_state->parent_pid = cpid;
}
struct timespec elapsed_time(const struct timespec start, const struct timespec stop) {
	struct timespec ret;

	if ((stop.tv_nsec - start.tv_nsec) < 0) {
		ret.tv_sec = stop.tv_sec - start.tv_sec - 1;
		ret.tv_nsec = 1000000000L + stop.tv_nsec - start.tv_nsec;
	} else {
		ret.tv_sec = stop.tv_sec - start.tv_sec;
		ret.tv_nsec = stop.tv_nsec - start.tv_nsec;
	}
	return ret;
}

void monitor_kill_all(int sig) {
	struct itimerval ntimeout;
	int i;

	signal(SIGALRM, SIG_IGN); /* ignore the timer if it alarms */
	ntimeout.it_interval.tv_sec = ntimeout.it_interval.tv_usec = 0;
	ntimeout.it_value.tv_sec  = ntimeout.it_value.tv_usec = 0;
	setitimer(ITIMER_REAL, &ntimeout, NULL);

	if (sig == SIGCHLD)
		sig = SIGTERM;
	for (i = 0 ; i < CHILD_PROC ; i ++)
		kill(test_state->child_pids[i], sig);
	kill(test_state->parent_pid, sig);
	write_freezer_thawed();

	/* disable rpc debugging */
	write_file_int(RPC_DEBUG_FILE, RPC_DEBUG_DISABLE);

	exit(EXIT_SUCCESS);
}

void monitor_show_stats(int sig) {
	static int in_interrupt = 0;
	static int hang_reported = 0;
	static struct timespec hang_start;
	unsigned long current_count;
	unsigned long interval_count;
	struct timespec current_time;
	enum frozen frozen;
	int hung = 0;

	if (in_interrupt)
		return;
	in_interrupt = 1;

	current_time = get_time();
	current_count = test_state->count;
	interval_count = current_count - test_state->last_count;
	struct timespec test_time =
		elapsed_time(test_state->start_time, current_time);

	frozen = test_state->frozen;
	if (!interval_count && frozen)
		hung = 1;
	if (!hung) {
		struct timespec interval_time =
			elapsed_time(test_state->last_time, current_time);

		hang_reported = 0;

		printf("%4ld.%03ld %10lu : %1ld.%03ld %10lu : %s\r",
			test_time.tv_sec, test_time.tv_nsec / 1000000UL, current_count,
			interval_time.tv_sec, interval_time.tv_nsec / 1000000UL, interval_count,
			frozen ? "FROZEN" : "THAWED");
	} else if (!hang_reported) {
		printf("\n***** Tasks appear hung while waiting for XPRT_LOCKED held by frozen task\n");
		syslog(LOG_ERR, "tasks appear hung waiting for XPRT_LOCKED held by frozen task\n");
		hang_reported = 1;
		hang_start = current_time;
	} else {
		struct timespec hang_time =
			elapsed_time(hang_start, current_time);

		printf("HUNG %4ld.%03ld\r",
			hang_time.tv_sec, hang_time.tv_nsec / 1000000UL);
	}
	fflush(stdout);

	test_state->last_time = current_time;
	test_state->last_count = current_count;

	in_interrupt = 0;
}

void monitor_work(void) {
	struct sigaction sa;
	struct itimerval timer;
	sigset_t sig_mask;
	int ret;

	openlog("test_freezer", LOG_PID | LOG_NOWAIT, LOG_USER);

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sa.sa_handler = &monitor_show_stats;
	ret = sigaction(SIGALRM, &sa, NULL);

	sa.sa_handler = &monitor_kill_all;
	ret = sigaction(SIGCHLD, &sa, NULL);
	ret = sigaction(SIGTERM, &sa, NULL);
	ret = sigaction(SIGINT, &sa, NULL);

	timer.it_value.tv_sec = timer.it_interval.tv_sec = MONITOR_INTERVAL_SEC;
	timer.it_value.tv_usec = timer.it_interval.tv_usec = MONITOR_INTERVAL_USEC;
	setitimer(ITIMER_REAL, &timer, 0);

	sigfillset(&sig_mask);
	sigdelset(&sig_mask, SIGCHLD);
	sigdelset(&sig_mask, SIGTERM);
	sigdelset(&sig_mask, SIGINT);
	sigdelset(&sig_mask, SIGALRM);

	while (1) {
		sigsuspend(&sig_mask);
	}
}

void do_setup(char *directory) {
	test_state = mmap(NULL, sizeof(struct state), PROT_READ|PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE,
		-1, 0);

	test_state->count = 0;
	test_state->frozen = THAWED;
	test_state->start_time = get_time();
	test_state->last_time = test_state->start_time;

	if (mkdir(CGROUP_BASE "/" FREEZER_CGROUP,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH) == -1) {
		if (errno != EEXIST) {
			printf("Error while creating cgroup: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		write_freezer_thawed();
	}

	/* enable rpc debugging */
	write_file_int(RPC_DEBUG_FILE, RPC_DEBUG_VALUE);
}

int main(int argc, char *argv[]) {
	char *directory;

	directory = argc > 1 ? argv[1] : ".";

	do_setup(directory);

	start_children(directory);
	start_parent(directory);
	monitor_work();

	return EXIT_SUCCESS;
}
