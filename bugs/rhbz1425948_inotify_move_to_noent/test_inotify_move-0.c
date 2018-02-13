/*
	Frank Sorenson <sorenson@redhat.com>
	Red Hat, 2017

	program to reproduce inotify MOVE_TO event
	with stat() of the new file returning ENOENT

	usage: test_inotify_move directory_to_monitor directory_to_monitor/filename

	# gcc test_inotify_move.c -o test_inotify_move -l pthread
	# ./test_inotify_move <staging_dir> <final_dir>

*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>
#include <sys/inotify.h>
#include <errno.h>
#include <syscall.h>
#include <dirent.h>

// binary trees
#include <search.h>


#define NUM_WD (100000ULL)

#define KiB (1024ULL)
#define BUF_SIZE (32ULL * KiB)

#define ITER_COUNT 10000
#define PROGRESS_INTERVAL 50 /* don't flood */
#define QUIET 1

#define exit_fail(args...) do { \
	printf("Error %d: %s - ", errno, strerror(errno)); \
	printf(args); exit(EXIT_FAILURE); } while (0)


#define unlikely(x)     __builtin_expect((x),0)
#define progress_counter(_ctr, _output) do { \
	if (unlikely( ! (--_ctr) )) { \
		printf(_output); \
		fflush(stdout); \
		_ctr = PROGRESS_INTERVAL; \
	} \
} while (0)

struct linux_dirent64 {
	ino64_t		d_ino;
	off64_t         d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[];
};


struct wd_entry {
	int wd;
	char *path;
};

struct wd_info_struct {
	void *tree_root;
	int active_wds;
	int inotify_fd;
//	int init_wd;
	char *base_path;
	struct wd_path_struct *wd_paths;
};

struct wd_entry *new_wd_entry(int wd, char *path) {
	struct wd_entry *wd_entry = calloc(sizeof(struct wd_entry), 1);
	if (!wd_entry)
		exit_fail("calloc failed: %m\n");
	wd_entry->wd = wd;
	wd_entry->path = strdup(path);
	return wd_entry;
}
void kill_wd_entry(void *w) {
	struct wd_entry *wd_entry = w;
	if (!wd_entry)
		return;
	free(wd_entry->path);
	free(wd_entry);
}
int compare_wd_entries(const void *p1, const void *p2) {
	const struct wd_entry *entry1 = p1;
	const struct wd_entry *entry2 = p2;
	if (entry1->wd < entry2->wd)
		return -1;
	if (entry1->wd > entry2->wd)
		return1;
	return 0;
}
void
walk_entry(const void *p, VISIT x,int level) {
	struct wd_entry *wd_entry = *(struct wd_entry **)p;
	printf("<%d>Walk on node %s %u %s  \n",
		level,
		x == preorder?"preorder":
		x == postorder?"postorder":
		x == endorder?"endorder":
		x == leaf?"leaf":
		"unknown",
		wd_entry->wd, wd_entry->path);
}



/*
	thread 1:
		monitor destination directory tree for MOVE_IN events
		when MOVE_IN event is delivered, stat the file, and report success/failure
	thread 2:
		create file in staging directory
		create destination directory (if necessary)
		move file to destination directory

*/

//pthread_t monitor_thread;
//pthread_t files_thread;

#define INOTIFY_BUFFER_SIZE 8192


void handle_events(struct wd_info_struct *wd_info) {
	char buf[INOTIFY_BUFFER_SIZE] __attribute__ ((aligned(__alignof__(struct inotify_event))));
	const struct inotify_event *event;
	int i;
	ssize_t len;
	char *ptr;
	char *event_wd_path;
	char *event_path;
	struct stat st;
	char *event_string;
	static unsigned long long counter = PROGRESS_INTERVAL;

	for (;;) {
		len = read(wd_info->inotify_fd, buf, sizeof buf);
		if (len == -1 && errno != EAGAIN) {
			perror("read");
			exit(EXIT_FAILURE);
		}

		if (len <= 0)
			break;
		for (ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
			event = (const struct inotify_event *) ptr;

			progress_counter(counter, ".");

			if (event->mask & IN_OPEN)
				event_string = "IN_OPEN: ";
			if (event->mask & IN_CLOSE_NOWRITE)
				event_string = "IN_CLOSE_NOWRITE: ";
			if (event->mask & IN_CLOSE_WRITE)
				event_string = "IN_CLOSE_WRITE: ";
			if (event->mask & IN_MOVED_TO)
				event_string = "IN_MOVED_TO: ";
//			if (event->mask & 

			event_wd_path = NULL;
			event_path = NULL;
			for (i = 0 ; i < NUM_WD ; i++) {
				if (event->wd == wd_info->wd_paths[i].wd) {
					event_wd_path = wd_info->wd_paths[i].path;
//					printf("wd: %d, path: %s\n", event->wd, wd_info->wd_paths[i].path);
					break;
				}
			}


			if (event->mask & IN_ISDIR) {
				printf("Error: unknown event type...\n");
				continue;
			}

			if (event->len) {
				asprintf(&event_path, "%s/%s", event_wd_path, event->name);
//				printf("%s", event->name);

//printf("event path: '%s'\n", event_path);

				if (stat(event_path, &st) == -1) {
					printf("Error calling stat() on '%s': %m\n", event_path);
					free(event_path);
					continue;
				}
				struct timespec ts;
				struct tm tm_info;
				char time_buffer[32];
				char tzbuf[8];
				char *output_buf;

				clock_gettime(CLOCK_REALTIME, &ts);
				localtime_r(&ts.tv_sec, &tm_info);
				strftime(time_buffer, 32, "%F %T", &tm_info);
				strftime(tzbuf, 8, "%Z", &tm_info);
				asprintf(&output_buf, "%s.%06ld %s", time_buffer, ts.tv_nsec / 1000, tzbuf);

				if ((setxattr(event_path, "user.date_detected", output_buf, strlen(output_buf) + 1, 0)) == -1) {
					printf("Failed to set xattr 'user.date_detected' to '%s' for '%s': %m\n", output_buf, event_path);
				}
//				printf("%s: %s moved in, size: %ld bytes\n", event_string, event_path, st.st_size);
				free(output_buf);
				free(event_path);
			}
		}
	}
}

static void shutdown_sigs(int signal_fd) {
	close(signal_fd);
}
static int init_sigs(void) {
	int signal_fd;
	sigset_t sigmask;

	sigemptyset (&sigmask);
	sigaddset (&sigmask, SIGINT);
	sigaddset (&sigmask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) < 0) {
		printf("Error blocking signals: %m\n");
		return -1;
	}

	if ((signal_fd = signalfd(-1, &sigmask, 0)) < 0) {
		printf("Error setting up signal fd: %m\n");
		return -1;
	}
	return signal_fd;
}

void add_watch_dir(struct wd_info_struct *wd_info, char *path) {
	int wd;
	struct wd_entry *new_ent;

	wd = inotify_add_watch(wd_info->inotify_fd, path, IN_MOVED_TO | IN_ATTRIB | IN_CREATE);
	new_ent = new_wd_entry(wd, path);
	tsearch(new_ent, &wd_info->tree_root, compare_wd_entries);
}
void add_watch_file(struct wd_info_struct *wd_info, char *path) {
	int wd;
	struct wd_entry *new_ent;

	wd = inotify_add_watch(wd_info->inotify_fd, path, IN_ATTRIB);
	new_ent = new_wd_entry(wd, path);
	tsearch(new_ent, &wd_info->tree_root, compare_wd_entries);
	/* screw safety...  I'm sure it got added just fine */

//	wd_info->wd_paths[wd_info->active_wds].wd =
//		inotify_add_watch(wd_info->inotify_fd, path, IN_ATTRIB);
//	wd_info->wd_paths[wd_info->active_wds].path = strdup(path);
//	wd_info->active_wds++;
}


void add_watches_recursive(struct wd_info_struct *wd_info, char *path){
	/* add self directory */
	/* iterate children, recurse for each dir */
	int wd;
	int i;
	int dir_fd;
	char buf[BUF_SIZE];
	char *bpos;
	int nread;
	struct linux_dirent64 *temp_de;
	struct stat st;

	stat(path, &st);
	if (S_ISREG(st.st_mode)) {
		printf("Adding watch for file: %s\n", path);
		add_watch_file(wd_info, path);
		return;
	}
	printf("Adding watch for dir: %s\n", path);
	add_watch_dir(wd_info, path);

	wd = inotify_add_watch(wd_info->inotify_fd, path, IN_MOVED_TO | IN_ATTRIB | IN_CREATE);
	i = wd_info->active_wds++;

	wd_info->wd_paths[i].wd = wd;
	wd_info->wd_paths[i].path = strdup(path);

        if ((dir_fd = open(path, O_RDONLY | O_DIRECTORY)) == -1)
                exit_fail("open call failed");
	for (;;) {
		nread = syscall(SYS_getdents64, dir_fd, buf, BUF_SIZE);

		if (nread == -1)
			return;
		if (nread == 0)
			break;

		bpos = buf;
		while (bpos < buf + nread) {
			temp_de = (struct linux_dirent64 *)bpos;
			bpos += temp_de->d_reclen;
			if ((!strcmp(temp_de->d_name, ".")) || (!strcmp(temp_de->d_name, "..")))
				continue;

			switch (temp_de->d_type) {
				case DT_UNKNOWN:
					fstatat(dir_fd, temp_de->d_name, &st, AT_SYMLINK_NOFOLLOW);
					if (!S_ISDIR(st.st_mode))
						break;
				;;
				case DT_DIR: {
					char *new_path;
					asprintf(&new_path, "%s/%s", path, temp_de->d_name);
					add_watches_recursive(wd_info, new_path);
					free(new_path);
					break;
				}
				case DT_REG: {
					char *new_path;
					asprintf(&new_path, "%s/%s", path, temp_de->d_name);
					wd = inotify_add_watch(wd_info->inotify_fd, new_path, IN_ALL_EVENTS);
					i = wd_info->active_wds++;
					wd_info->wd_paths[i].wd = wd;
					wd_info->wd_paths[i].path = strdup(new_path);
					free(new_path);
					
					break;
				}
				default:
					break;
			}
		}
	}
	close(dir_fd);
}


int main(int argc, char *argv[]) {
	char buf;
//	int fd, i, poll_num;
	int i, poll_num;
	nfds_t nfds;
	struct pollfd fds[2];
//	struct stat st;

	if (argc < 2) {
		printf("Usage: %s PATH [PATH ...]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	printf("Press ENTER key to terminate.\n");

	/* Create the file descriptor for accessing the inotify API */

	struct wd_info_struct *wd_info = malloc(sizeof(struct wd_info_struct));
	if ((wd_info->inotify_fd = inotify_init1(IN_NONBLOCK)) == -1) {
		perror("inotify_init1");
		exit(EXIT_FAILURE);
	}

	shared_data->tree_root = NULL;


	wd_info->wd_paths = malloc(sizeof(struct wd_path_struct) * NUM_WD);
	for (i = 0 ; i < NUM_WD ; i++)
		wd_info->wd_paths[i].wd = -1;

	wd_info->active_wds = 0;
	wd_info->base_path = canonicalize_file_name(argv[1]);
	add_watches_recursive(wd_info, wd_info->base_path);

           /* Mark directories for events
              - file was opened
              - file was closed */
/*
		for (i = 1; i < argc; i++) {
		wd[i] = inotify_add_watch(fd, argv[i], IN_MOVED_TO | IN_ATTRIB);
		if (wd[i] == -1) {
			fprintf(stderr, "Cannot watch '%s'\n", argv[i]);
			perror("inotify_add_watch");
			exit(EXIT_FAILURE);
		}
		stat(wd[i], &st);
		if ((


	}
*/
	/* Prepare for polling */

	nfds = 2;

	/* Console input */

	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;

	/* Inotify input */

	fds[1].fd = wd_info->inotify_fd;
	fds[1].events = POLLIN;

	/* Wait for events and/or terminal input */

	printf("Listening for events.\n");
	while (1) {
		poll_num = poll(fds, nfds, -1);
		if (poll_num == -1) {
			if (errno == EINTR)
				continue;
			perror("poll");
			exit(EXIT_FAILURE);
		}

		if (poll_num > 0) {

			if (fds[0].revents & POLLIN) {
				/* Console input is available. Empty stdin and quit */

				while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
					continue;
				break;
			}

			/* Inotify events are available */
			if (fds[1].revents & POLLIN)
				handle_events(wd_info);
		}
	}

	printf("Listening for events stopped.\n");

	/* Close inotify file descriptor */
	close(wd_info->inotify_fd);

//           free(wd);
	return EXIT_SUCCESS;
}
