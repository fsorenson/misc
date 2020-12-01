#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

struct tree_level_info {
	int subdirs;
	int files;
};

struct tree_level_info tree_levels[] = {
	{ .subdirs = 10, .files = 0 },
	{ .subdirs = 10, .files = 0 },
	{ .subdirs = 100, .files = 0 },
	{ .subdirs = 100, .files = 0 },
	{ .subdirs = 0, .files = 10 },
};

static int tree_level_count = sizeof(tree_levels)/sizeof(tree_levels[0]);
#define DIR_NAME_PATTERN "dir-%03d"
#define FILE_NAME_PATTERN "file-%03d"

pid_t *cpids = NULL;
int running_cpids = 0;
int num_threads;

void set_sigaction(int signum, sighandler_t handler) {
        struct sigaction sa;

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sa.sa_handler = handler;

        sigaction(signum, &sa, NULL);
}
static void handle_child(int sig) {
	pid_t cpid;
	int i;

	while ((cpid = wait4(-1, NULL, WNOHANG, NULL)) != -1) {
		if (cpid == 0)
			return;
		for (i = 0 ; i < num_threads ; i++) {
			if (cpid == cpids[i]) {
				cpids[i] = 0;
				i = num_threads;
			}

		}
	}
	running_cpids = 0;
	for (i = 0 ; i < num_threads ; i++) {
		if (cpids[i])
			running_cpids++;
	}
}

static void interrupt(int sig) {
	int i;

	for (i = 0 ; i < num_threads ; i++) {
		if (cpids[i])
			if ((kill(cpids[i], SIGINT)) < 0)
				output("parent got error while killing child %d (pid %d): %m\n",
					i, cpids[i]);
	}
}

void create_files(int dfd, int count) {
	char *filename;
	int fd, i;

	asprintf(&filename, FILE_NAME_PATTERN, 0);
	for (i = 0 ; i < count ; i++) {
		sprintf(filename, FILE_NAME_PATTERN, i);
		if ((fd = openat(dfd, filename, O_CREAT|O_TRUNC|O_WRONLY, 0644)) < 0) {
			if (errno != EEXIST) {
				output("error opening file '%s': %m\n", filename);
				exit(EXIT_FAILURE);
			}
		}
		close(fd);
	}
	free(filename);
}

void create_tree_level(int level, int dfd) {
	int i;

	if (level >= tree_level_count)
		return;

	if (tree_levels[level].subdirs) {
		char *dirname;
		int next_dfd;

		asprintf(&dirname, DIR_NAME_PATTERN, tree_levels[level].subdirs);
		for (i = 0 ; i < tree_levels[level].subdirs ; i++) {
			sprintf(dirname, DIR_NAME_PATTERN, i);
			if ((mkdirat(dfd, dirname, 0755)) < 0) {
				if (errno != EEXIST) {
					output("error creating '%s': %m\n", dirname);
					exit(EXIT_FAILURE);
				}
			}
			if (level < tree_level_count) {
				if ((next_dfd = openat(dfd, dirname, O_RDONLY|O_DIRECTORY)) < 0) {
					output("error opening '%s': %m\n", dirname);
					exit(EXIT_FAILURE);
				}
				create_tree_level(level + 1, next_dfd);
				close(next_dfd);
			}
		}
		free(dirname);
	}
	if (tree_levels[level].files)
		create_files(dfd, tree_levels[level].files);
}

void child_work(int child_id, int dfd) {
	char *dirname;

	asprintf(&dirname, DIR_NAME_PATTERN, child_id);
	if ((mkdirat(dfd, dirname, 0755)) < 0) {
		if (errno != EEXIST) {
			output("error creating '%s': %m\n", dirname);
			exit(EXIT_FAILURE);
		}
	}

	if (tree_level_count > 1) {
		int next_dfd;

		if ((next_dfd = openat(dfd, dirname, O_RDONLY|O_DIRECTORY)) < 0) {
			output("error opening '%s': %m\n", dirname);
			exit(EXIT_FAILURE);
		}
		create_tree_level(1, next_dfd);
		close(next_dfd);
	}

	free(dirname);
}

int main(int argc,  char *argv[]) {
	sigset_t signal_mask;
	char *path = ".";
	int child_id;
	pid_t cpid;
	int dfd;

	if (argc == 2)
		path = argv[1];

	if ((dfd = open(path, O_RDONLY|O_DIRECTORY)) < 0) {
		output("error opening base directory '%s': %m\n", path);
		exit(EXIT_FAILURE);
	}

	num_threads = tree_levels[0].subdirs;
	if (num_threads)
		cpids = calloc(num_threads, sizeof(*cpids));

	for (child_id = 0 ; child_id < tree_levels[0].subdirs ; child_id++) {
		if ((cpid = fork()) == 0) {
			child_work(child_id, dfd);
			return EXIT_SUCCESS;
		}
		cpids[child_id] = cpid;
		running_cpids++;
	}

	set_sigaction(SIGCHLD, &handle_child);
	set_sigaction(SIGINT, &interrupt);
	set_sigaction(SIGTERM, &interrupt);

	if (tree_levels[0].files) {
		create_files(dfd, tree_levels[0].files);
	}

	sigfillset(&signal_mask);
	sigdelset(&signal_mask, SIGCHLD);
	sigdelset(&signal_mask, SIGINT);
	sigdelset(&signal_mask, SIGTERM);

	while (running_cpids > 0)
		sigsuspend(&signal_mask);

	if (cpids)
		free(cpids);

	return EXIT_SUCCESS;
}
