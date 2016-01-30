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
#include <signal.h>

#define FREEZER_CGROUP "test_cgroup"
#define CGROUP_BASE "/cgroup/freezer"
#define CGROUP_STATE_FILE CGROUP_BASE "/" FREEZER_CGROUP "/freezer.state"
#define CGROUP_TASK_FILE CGROUP_BASE "/" FREEZER_CGROUP "/tasks"

#define FREEZABLE_COUNT 5
#define BUF_LEN_PID_STRING 15

pid_t freeze_pids[FREEZABLE_COUNT];
pid_t worker_pid;

#define write_file_string(_file, _buf) do { \
	int fd; \
	if ((fd = open(_file, O_WRONLY | O_SYNC)) >= 0) { \
		write(fd, _buf, strlen(_buf)); \
		close(fd); \
	} \
} while (0)

#define write_freezer_thawed() do { \
	write_file_string(CGROUP_STATE_FILE, "THAWED"); \
} while (0)
#define write_freezer_frozen() do { \
	write_file_string(CGROUP_STATE_FILE, "FROZEN"); \
} while (0)

#define write_file_int(_file, _val) do { \
	char buf[BUF_LEN_PID_STRING]; \
	snprintf(buf, BUF_LEN_PID_STRING, "%d", _val); \
	write_file_string(_file, buf); \
} while (0)
#define write_pid_file(p) write_file_int(CGROUP_TASK_FILE, p)

void do_stat_work(char *directory) {
	struct stat st;

	while (1) {
		stat(directory, &st);
	}
}

void do_work(char *directory) {
	struct stat st;

	while (1) {
		write_freezer_frozen();
		stat(directory, &st);
		write_freezer_thawed();
	}
}

void monitor_kill_all(int sig) {
	int i;

	if (sig == SIGCHLD)
		sig = SIGTERM;
	for (i = 0 ; i < FREEZABLE_COUNT ; i ++)
		kill(freeze_pids[i], sig);
	kill(worker_pid, sig);
	write_freezer_thawed();

	exit(EXIT_SUCCESS);
}

void monitor_work(char *directory) {
	struct sigaction sa;
	sigset_t sig_mask;
	int ret;
	int i;
	pid_t cpid;

	for (i = 0 ; i < FREEZABLE_COUNT ; i ++) {
		if ((cpid = fork()) == 0)
			do_stat_work(directory);
		freeze_pids[i] = cpid;
		write_pid_file(freeze_pids[i]);
	}

	if ((cpid = fork()) == 0)
		do_work(directory);
	worker_pid = cpid;

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;

	sa.sa_handler = &monitor_kill_all;
	ret = sigaction(SIGCHLD, &sa, NULL);
	ret = sigaction(SIGTERM, &sa, NULL);
	ret = sigaction(SIGINT, &sa, NULL);

	sigfillset(&sig_mask);
	sigdelset(&sig_mask, SIGCHLD);
	sigdelset(&sig_mask, SIGTERM);
	sigdelset(&sig_mask, SIGINT);

	while (1) {
		sigsuspend(&sig_mask);
	}
}

int main(int argc, char *argv[]) {
	char *directory;

	directory = argc > 1 ? argv[1] : ".";

	if (mkdir(CGROUP_BASE "/" FREEZER_CGROUP,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH) == -1) {
		if (errno != EEXIST) {
			printf("Error while creating cgroup: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		write_freezer_thawed();
	}

	monitor_work(directory);

	return EXIT_SUCCESS;
}
