/*
	Frank Sorenson <sorenson@redhat.com>, 2023

*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>


#define KiB                     (1024UL)
#define MiB                     (KiB * KiB)
#define GiB                     (KiB * KiB * KiB)

#define USEC_TO_NSEC(v)         (v * 1000UL)
#define MSEC_TO_NSEC(v)         (v * 1000000UL)
#define NSEC                    (1000000000UL)

#define GETDENTS_BUF_SIZE (64UL * KiB)
#define MAX_DEPTH 20
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

char *getdents_buffers[MAX_DEPTH];
char *path_buffers[MAX_DEPTH];
uint64_t counts[MAX_DEPTH + 1];
bool delete_tree = false;

int verbosity = 0;
pid_t tid = -1;
int child_id = -1;
int children = 0;
int running_cpids = 0;
int *cpids = NULL;

pid_t gettid(void) {
	return syscall(SYS_gettid);
}

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define free_mem(var) do { \
	if (var) \
		free(var); \
	var = NULL; \
} while (0)

struct linux_dirent64 {
	ino64_t		d_ino;		// 64-bit inode number
	off64_t		d_off;		// 64-bit offset to next structure
	unsigned short	d_reclen;	// Size of this dirent
	unsigned char	d_type;		// File type
	char		d_name[];	// Filename (null-terminated)
};

void output_counts(int sig) {
	(void)sig;
	int i;

	output("%" PRIu64 ": ", counts[MAX_DEPTH]);
	for (i = 0 ; i < MAX_DEPTH ; i++) {
		output("%" PRIu64 " / ", counts[i]);
		if (counts[i] == 0)
			break;
	}
	output("\r");
}

static void handle_child(int sig) {
	pid_t cpid;
	int i;

	while ((cpid = wait4(-1, NULL, WNOHANG, NULL)) != -1) {
		if (cpid == 0)
			return;
		for (i = 0 ; i < children ; i++) {
			if (cpid == cpids[i]) {
				cpids[i] = 0;
				i = children;
			}
		}
	}
	running_cpids = 0;
	for (i = 0 ; i < children ; i++) {
		if (cpids[i])
			running_cpids++;
	}
}





int walk_path(int dfd, const char *path, int depth) {
	struct linux_dirent64 *de;
	char *getdents_buf = NULL, *bpos;
	int ret = EXIT_SUCCESS, nread;
	struct stat st;

	if (depth >= MAX_DEPTH) {
		output("depth exceeded\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	getdents_buf = getdents_buffers[depth];

	while (42) {
		if ((nread = syscall(SYS_getdents64, dfd, getdents_buf, GETDENTS_BUF_SIZE)) < 0) {
			fstatat(dfd, "", &st, AT_EMPTY_PATH);
			output("error getting directory entries in '%s', inode # %lu: %m\n", path, st.st_ino);
			ret = EXIT_FAILURE;
			goto out;
		}
		if (nread == 0)
			break;

		bpos = getdents_buf;
		while (bpos < getdents_buf + nread) {
			struct stat st;

			de = (struct linux_dirent64 *)bpos;
			bpos += de->d_reclen;

			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;

			counts[depth]++;
			counts[MAX_DEPTH]++;
			if (counts[MAX_DEPTH] % 100 == 0)
				output_counts(0);

			if (de->d_type != DT_DIR) {
				if (delete_tree) {
					if (verbosity)
						output("%d - deleting '%s/%s'\n", tid, path, de->d_name);
					if ((unlinkat(dfd, de->d_name, 0)) < 0)
						output("%d - error deleting '%s/%s': %m\n", tid, path, de->d_name);
				} else {
					if ((fstatat(dfd, de->d_name, &st, 0)) < 0) {
						output("%d - error statting '%s/%s'\n", tid, path, de->d_name);
						ret = EXIT_FAILURE;
						goto out;
					}
					continue;
				}
				continue;
			}

			int next_dfd;
			snprintf(path_buffers[depth], PATH_MAX - 1, "%s/%s", path, de->d_name);
			if ((next_dfd = openat(dfd, de->d_name, O_RDONLY|O_DIRECTORY)) < 0) {
				output("%d - error opening directory '%s': %m\n", tid, path_buffers[depth]);
				ret = EXIT_FAILURE;
				goto out;
			}
			ret = walk_path(next_dfd, path_buffers[depth], depth + 1);
			close(next_dfd);
			if (ret != EXIT_SUCCESS)
				goto out;
			if (delete_tree) {
				if (verbosity)
					output("%d - removing directory '%s/%s'\n", tid, path, de->d_name);
				if ((unlinkat(dfd, de->d_name, AT_REMOVEDIR)) < 0) {
					output("%d - error removing directory '%s/%s': %m\n", tid, path, de->d_name);
				}
			}
		}
	}
out:
	return ret == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

int usage(const char *exe, int ret) {
	output("usage: %s [ -d | --delete ] <starting path>\n", exe);
	return ret;
}


static struct option long_opts[] = {
	{ "delete", no_argument, NULL, 'd' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "children", required_argument, NULL, 'c' },
	{ NULL, 0, 0, 0 },
};

int main(int argc, char *argv[]) {
	int ret = EXIT_FAILURE, i;
	const char *path;
	int arg, dfd;

	while ((arg = getopt_long(argc, argv, "c:dhv", long_opts, NULL)) != EOF) {
		switch (arg) {
			case 'c':
				children = strtol(optarg, NULL, 10); break;
			case 'd':
//				output("deleting visited files/dirs\n");
				delete_tree = true; break;
			case 'v':
				verbosity++; break;
			case 'h':
				return usage(argv[0], EXIT_SUCCESS); break;
			default:
				return usage(argv[0], EXIT_FAILURE); break;
		}
	}

        if (argc < optind + 1)
                return usage(argv[0], EXIT_FAILURE);


	for (i = 0 ; i < MAX_DEPTH ; i++) {
		getdents_buffers[i] = malloc(GETDENTS_BUF_SIZE);
		path_buffers[i] = malloc(PATH_MAX);
	}

	tid = gettid();
	struct sigaction sa;
	struct itimerval timer;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &output_counts;

	timer.it_value.tv_sec = timer.it_interval.tv_sec = 15;
	timer.it_value.tv_usec = timer.it_interval.tv_usec = 0;

	sigaction(SIGALRM, &sa, NULL);
	setitimer(ITIMER_REAL, &timer, 0);

	while (optind < argc) {
		path = argv[optind++];
		if (!strcmp(path, "..")) {
			output("%d - cowardly refusing to delete my parent directory\n", tid);
			continue;
		}

		if (verbosity)
			output("%d - removing tree at '%s'\n", tid, path);


		if ((dfd = openat(AT_FDCWD, path, O_RDONLY|O_DIRECTORY, 0)) < 0) {
			output("error opening path '%s': %m\n", path);
			ret = EXIT_FAILURE;
			continue;
		}

		ret = walk_path(dfd, path, 0);
		close(dfd);
		if ((unlinkat(AT_FDCWD, path, AT_REMOVEDIR)) < 0) {
			output("error deleting dir: %m\n");
		}
	}

	ret = EXIT_SUCCESS;

out:
	output_counts(0);
	output("\n");
	return ret;
}
