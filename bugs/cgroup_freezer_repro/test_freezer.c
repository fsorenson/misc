/*
	Frank Sorenson <sorenson@redhat.com>, 2015

	Test process freeze/thaw using cgroups to reproduce
	condition where task can become frozen while holding
	key rpc-related locks

	# gcc test_freezer.c -o test_freezer
	# ./test_freezer [<path_on_nfs>]

	parent task:
		create freezer cgroup
		start m of child 1 & n of child 2
		add child pids to freezer cgroup
		while (1)
			freeze cgroup
			stat(directory)
			thaw cgroup

	child type 1:
		fd = open(<path>/testfile_00)
		while(1)
			pwrite(fd, buf)
			...
	child type 2:
		while (1)
			access(test_file)
			stat(test_file)

	current settings are:
		0 child type 1
		100 child type 2
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
#include <sched.h>


#define KiB (1024UL)
#define MiB (KiB * KiB)

#define BUF_SIZE	(1UL * MiB)
#define TEST_FILE_SIZE	(500UL * MiB)

#define FREEZER_CGROUP "test_cgroup"
#define CGROUP_BASE "/cgroup/freezer"
#define CGROUP_STATE_FILE CGROUP_BASE "/" FREEZER_CGROUP "/freezer.state"
#define CGROUP_TASK_FILE CGROUP_BASE "/" FREEZER_CGROUP "/tasks"

#define CHILD_PROC1 0
#define CHILD_PROC2 100

pid_t pids1[CHILD_PROC1];
pid_t pids2[CHILD_PROC2];

void child_work(char *directory) {
	int fd;
	char *test_file;
	char *buf;
	unsigned long pos;

	asprintf(&test_file, "%s/testfile_00", directory);

	fd = open(test_file, O_WRONLY | O_CREAT | O_DIRECT | O_SYNC,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1) {
		printf("Error opening file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	buf = malloc(BUF_SIZE);
	memset(buf, 0xAA, BUF_SIZE);

	while (1) {
		pos = 0;
		while (pos < TEST_FILE_SIZE) {
			if (pwrite(fd, buf, BUF_SIZE, pos) != BUF_SIZE) {
				printf("Error writing to file: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
			pos += BUF_SIZE;
		}
	}

	/* how we got here, I do not know, but better safe than sorry...  maybe? */
	free(buf);
	close(fd);
	free(test_file);
}

void child_work2(char *directory) {
	struct stat st;
	char *test_file;
	int ret;

	asprintf(&test_file, "%s/testfile_00", directory);

	while (1) {
		ret = access(test_file, R_OK | W_OK);
		stat(test_file, &st);
	}

	/* how we got here, I do not know, but better safe than sorry...  maybe? */
	free(test_file);
}

#define _write_file_string(_file, _buf, _opt) do { \
	int fd; \
	char *__buf = _buf; \
	if ((fd = open(_file, O_WRONLY | O_SYNC)) >= 0) { \
		write(fd, __buf, strlen(__buf)); \
		close(fd); \
	} \
} while (0)

#define write_file_string(_file, _buf) do { \
	_write_file_string(_file, _buf, 0); \
} while (0)

#define BUF_LEN_PID_STRING 16
#define write_file_pid(_file, _val) do { \
	char buf[BUF_LEN_PID_STRING]; \
	snprintf(buf, BUF_LEN_PID_STRING, "%d", _val); \
	write_file_string(_file, buf); \
} while (0)

#define write_freezer_thawed() do { \
	write_file_string(CGROUP_STATE_FILE, "THAWED"); \
} while (0)
#define write_freezer_frozen() do { \
	write_file_string(CGROUP_STATE_FILE, "FROZEN"); \
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

//void parent_work(char *directory, pid_t cpid) {
void parent_work(char *directory) {
	struct stat st;
	int ret;
	unsigned long i = 0;

//	printf("child process is %d\n", cpid);
	printf("pid file is %s\n", CGROUP_TASK_FILE);

	if ((ret = mkdir(CGROUP_BASE "/" FREEZER_CGROUP,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)) == -1) {
		if (errno != EEXIST) {
			printf("Error while creating cgroup: %s\n", strerror(errno));
			goto err_exit;
		}
		write_freezer_thawed();
	}

	for (i = 0 ; i < CHILD_PROC1 ; i ++)
		write_pid_file(pids1[i]);
	for (i = 0 ; i < CHILD_PROC2 ; i ++)
		write_pid_file(pids2[i]);

//	write_pid_file(cpid);

	while (1) {
		if (i++ % 100000 == 0) {
			printf(".");
			fflush(stdout);
		}
		write_freezer_frozen();

		stat(directory, &st);

		write_freezer_thawed();
	}

err_exit:
	for (i = 0 ; i < CHILD_PROC1 ; i ++)
		kill(pids1[i], SIGTERM);
	for (i = 0 ; i < CHILD_PROC2 ; i ++)
		kill(pids2[i], SIGTERM);

//	kill(cpid, SIGTERM);
	exit(EXIT_FAILURE);
}

void start_children(char *directory) {
	int i;
	pid_t cpid;

	for (i = 0 ; i < CHILD_PROC1 ; i ++) {
		cpid = fork();
		if (cpid == 0)
			child_work(directory);
		pids1[i] = cpid;
	}
	for (i = 0 ; i < CHILD_PROC2 ; i ++) {
		cpid = fork();
		if (cpid == 0)
			child_work2(directory);
		pids2[i] = cpid;
	}
}

int main(int argc, char *argv[]) {
	char *directory;
//	pid_t cpid;

	directory = argc > 1 ? argv[1] : ".";

	start_children(directory);

	parent_work(directory);

	return EXIT_SUCCESS;
}
