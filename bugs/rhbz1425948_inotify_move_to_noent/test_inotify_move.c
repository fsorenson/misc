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

/* hopefully temporary */
#include <inotifytools/inotify.h>
#include <inotifytools/inotifytools.h>

// binary trees
#include <search.h>

#define FOUND_XATTR "user.found"

#define NUM_WD (100000ULL)

#define KiB (1024ULL)
#define BUF_SIZE (32ULL * KiB)
#define MAX_EVENT_STRLEN (4ULL * KiB)

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


struct watchent {
	int wd;
	char *path;
};

struct wd_info_struct {
	void *tree_root;
	int active_wds;
	int inotify_fd;
//	int init_wd;
	struct wd_path_struct *wd_paths;
};

struct watchent *new_watchent(int wd, char *path) {
	struct watchent *watchent = calloc(sizeof(struct watchent), 1);
	if (!watchent)
		exit_fail("calloc failed: %m\n");
	watchent->wd = wd;
	if (path)
		watchent->path = strdup(path);
	return watchent;
}
void kill_watchent(void *w) {
	struct watchent *watchent = w;
	if (!watchent)
		return;
	if (watchent->path)
		free(watchent->path);
	free(watchent);
}
int compare_wd_entries(const void *p1, const void *p2) {
	const struct watchent *entry1 = p1;
	const struct watchent *entry2 = p2;
	if (entry1->wd < entry2->wd)
		return -1;
	if (entry1->wd > entry2->wd)
		return 1;
	return 0;
}
void walk_entry(const void *p, VISIT x,int level) {
	struct watchent *watchent = *(struct watchent **)p;
	printf("<%d>Walk on node %s %u %s  \n",
		level,
		x == preorder?"preorder":
		x == postorder?"postorder":
		x == endorder?"endorder":
		x == leaf?"leaf":
		"unknown",
		watchent->wd, watchent->path);
}
void walk_entry2(const void *p, VISIT x,int level) {
	struct watchent *watchent = *(struct watchent **)p;

	if (x == leaf || x == postorder) {
		printf("<%d>Walk on node %s %u %s  \n",
			level,
			x == preorder?"preorder":
			x == postorder?"postorder":
			x == endorder?"endorder":
			x == leaf?"leaf":
			"unknown",
			watchent->wd, watchent->path);
	}
}

struct timespec tstamp_to_timespec(const char *tstamp) {
	char *tstamp_nons;
	struct timespec ts;
	struct tm tm;
	char *p;
	int len;

	len = strlen(tstamp);
	tstamp_nons = malloc(len - 10);
	strncpy(tstamp_nons, tstamp, 19);
	strncpy(tstamp_nons + 19, tstamp + 29, len - 29);

	p = strptime(tstamp_nons, "%F %T %Z", &tm);
	if (*p == '\0') {
		ts.tv_sec = mktime(&tm);
		ts.tv_nsec = strtol(tstamp + 20, &p, 10);
	} else {
		printf("doh!.  p=%s\n", p);
	}
	free(tstamp_nons);
	return ts;
}

char *create_tstamp(void) {
	struct timespec ts;
	struct tm tm_info;
	char time_buffer[32];
	char tzbuf[8];
	char *tstamp;

	clock_gettime(CLOCK_REALTIME, &ts);
	localtime_r(&ts.tv_sec, &tm_info);
	strftime(time_buffer, 32, "%F %T", &tm_info);
	strftime(tzbuf, 8, "%Z", &tm_info);
	asprintf(&tstamp, "%s.%09ld %s", time_buffer, ts.tv_nsec, tzbuf);

	return tstamp;
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
	struct watchent *new_ent;

	printf("Adding watch for dir: %s\n", path);
	wd = inotify_add_watch(wd_info->inotify_fd, path, IN_MOVED_TO | IN_ATTRIB | IN_CREATE);
	new_ent = new_watchent(wd, path);
	tsearch(new_ent, &wd_info->tree_root, compare_wd_entries);
}
void add_watch_file(struct wd_info_struct *wd_info, char *path) {
	struct watchent *new_ent;
	int wd;


	printf("Adding watch for file: %s\n", path);

	wd = inotify_add_watch(wd_info->inotify_fd, path, IN_ATTRIB);
	new_ent = new_watchent(wd, path);
	tsearch(new_ent, &wd_info->tree_root, compare_wd_entries);
}

char *create_event_string(const struct inotify_event *event) {
	char *event_string;
	int ret;

	event_string = malloc(MAX_EVENT_STRLEN+1);
	ret = inotifytools_snprintf(event_string, MAX_EVENT_STRLEN, event, "%s");
	if (ret != -1)
		return event_string;
	free(event_string);
	return strdup("UNKNOWN");
}

void do_file_work(char *path, struct stat *st) {
	/* here is where we'd do some work/actions for each file */
}

void process_file(struct wd_info_struct *wd_info, char *path) {
	/* startup behavior: */
	/* check whether it has an extended attribute */

	char *event_string = "UNKNOWN";
	char *xattr_string = NULL;
	char *tstamp;
	struct stat st;
	ssize_t len;

	if (stat(path, &st) == -1) {
		printf("Error calling stat() on '%s': %m\n", path);
		return;
	}


	len = getxattr(path, FOUND_XATTR, xattr_string, 0);
	if (len > 0) {
		xattr_string = malloc(len);
		len = getxattr(path, FOUND_XATTR, xattr_string, len);
		printf("%s already has '" FOUND_XATTR "' = '%s'\n", path, xattr_string);
		/* re-process the file, or ignore since already-processed? */
		free(xattr_string);
		return;
	}
	if (len < 0 && errno == ENOTSUP) /* kinda pointless to test on this filesystem, no? */
		exit_fail("Filesystem does not appear to support xattrs\n");

	stat(path, &st);
	tstamp = create_tstamp();
	printf("%s: processing %s, size: %ld bytes\n", event_string, path, st.st_size);
	if ((setxattr(path, FOUND_XATTR, tstamp, strlen(tstamp) + 1, 0)) == -1) {
		printf("WARNING: Failed to set xattr '" FOUND_XATTR "' to '%s' for '%s': %m\n", tstamp, path);
	} else {
		do_file_work(path, &st);
	}
	free(tstamp);
}

/*
<0>Walk on node preorder 2 /home/sorenson/RH/case_remnants/bz1425948_inotify_move_to_noent/final/foo  
<1>Walk on node leaf 1 /home/sorenson/RH/case_remnants/bz1425948_inotify_move_to_noent/final  
<0>Walk on node postorder 2 /home/sorenson/RH/case_remnants/bz1425948_inotify_move_to_noent/final/foo  
<1>Walk on node preorder 4 /home/sorenson/RH/case_remnants/bz1425948_inotify_move_to_noent/final3  
<2>Walk on node leaf 3 /home/sorenson/RH/case_remnants/bz1425948_inotify_move_to_noent/final2  
<1>Walk on node postorder 4 /home/sorenson/RH/case_remnants/bz1425948_inotify_move_to_noent/final3  
<2>Walk on node leaf 5 /home/sorenson/RH/case_remnants/bz1425948_inotify_move_to_noent/final4  
<1>Walk on node endorder 4 /home/sorenson/RH/case_remnants/bz1425948_inotify_move_to_noent/final3  
<0>Walk on node endorder 2 /home/sorenson/RH/case_remnants/bz1425948_inotify_move_to_noent/final/foo  
*/
int get_tree_size(struct wd_info_struct *wd_info) {
	int tree_size = 0;
	void walk_tree_size(const void *p, VISIT x,int level) {
		if (x == leaf || x == postorder)
			tree_size++;
	}
	twalk(wd_info->tree_root, walk_tree_size);
	return tree_size;
}


void add_watches_recursive(struct wd_info_struct *wd_info, char *path){
	/* add self directory */
	/* iterate children, recurse for each dir */
	int dir_fd;
	char buf[BUF_SIZE];
	char *bpos;
	int nread;
	struct linux_dirent64 *temp_de;
	struct stat st;

	stat(path, &st);
	if (S_ISREG(st.st_mode)) {
		add_watch_file(wd_info, path);
		return;
	}
	add_watch_dir(wd_info, path);

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
					if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
						break;
				;;
				case DT_DIR:
				case DT_REG: {
					char *new_path;
					asprintf(&new_path, "%s/%s", path, temp_de->d_name);
					add_watches_recursive(wd_info, new_path);
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

void handle_events(struct wd_info_struct *wd_info) {
	char buf[INOTIFY_BUFFER_SIZE] __attribute__ ((aligned(__alignof__(struct inotify_event))));
	const struct inotify_event *event;
	ssize_t len;
	char *ptr;
	char *wd_event_path;
	char *event_path;
//	struct stat st;
	char *event_string;
//	static unsigned long long counter = PROGRESS_INTERVAL;
	struct watchent *tmp_watchent;
	struct watchent *tree_watchent;

	for (;;) {
		len = read(wd_info->inotify_fd, buf, sizeof(buf));
		if (len == -1 && errno != EAGAIN)
			exit_fail("error reading from inotify_fd: %m\n");

		if (len <= 0)
			break;
		for (ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
			event = (const struct inotify_event *) ptr;

//			progress_counter(counter, ".");

			/* expected events */
			/* directory gets MOVED_TO event */
			/* file gets ATTR event (file date/time updated) */
			/* directory gets ATTR event (do we care?) */
			/* directory gets CREATE event (new directory created) */

			/* directory gets an IN_DELETE_SELF (directory is removed */
			/* file gets an IN_DELETE_SELF (file is deleted) */
			/*      parent directory will also get an IN_DELETE event */



/*
			if (event->mask & IN_OPEN)
				event_string = "IN_OPEN: ";
			if (event->mask & IN_CLOSE_NOWRITE)
				event_string = "IN_CLOSE_NOWRITE: ";
			if (event->mask & IN_CLOSE_WRITE)
				event_string = "IN_CLOSE_WRITE: ";
			if (event->mask & IN_MOVED_TO)
				event_string = "IN_MOVED_TO: ";
			if (event->mask & IN_ATTRIB)
				event_string = "IN_ATTRIB: ";
*/

			event_string = create_event_string(event);


//			printf("got event on wd %d\n", event->wd);
			tmp_watchent = new_watchent(event->wd, 0);
			tree_watchent = tfind(tmp_watchent, &wd_info->tree_root, compare_wd_entries);
			free(tmp_watchent);

			if (tree_watchent) {
				tree_watchent = *(struct watchent **)tree_watchent;

			} else {
				printf("did not find a matching watchent for event: %s\n", event_string);
				free(event_string);
				continue;
			}

//			printf("result: wd=%d, path=%s\n", tree_watchent->wd, tree_watchent->path);
			wd_event_path = tree_watchent->path;
//			printf("path: %s\n", tree_watchent->path);

			if (event->mask & IN_ISDIR) {
				asprintf(&event_path, "%s/%s", wd_event_path, event->name);
				if (event->mask & IN_CREATE) { /* hopefully it's a dir */
					add_watches_recursive(wd_info, event_path);
					free(event_path);
					free(event_string);
					continue;
				}

				printf("Unhandled event on directory '%s': %s\n", event_path, event_string);
				free(event_path);
				free(event_string);
				continue;
			}

			if (event->len) {
				asprintf(&event_path, "%s/%s", wd_event_path, event->name);
//				printf("%s", event->name);

//printf("event path: '%s'\n", event_path);
printf("'%s' for file '%s'\n", event_string, event_path);


				process_file(wd_info, event_path);



/*
				if (stat(event_path, &st) == -1) {
					printf("Error calling stat() on '%s': %m\n", event_path);
					free(event_path);
					free(event_string);
					continue;
				}

				char *xattr_string;
				ssize_t len;

				len = getxattr(event_path, FOUND_XATTR, xattr_string, 0);
				if (len > 0) {
					xattr_string = malloc(len);
					len = getxattr(event_path, FOUND_XATTR, xattr_string, len);
					printf("%s already has '" FOUND_XATTR "' = '%s'\n", event_path, xattr_string);
					free(xattr_string);
					continue;
				}
				if (len < 0 && errno == ENOTSUP)
					continue;


				char *tstamp;

				tstamp = create_tstamp();
				if ((setxattr(event_path, FOUND_XATTR, tstamp, strlen(tstamp) + 1, 0)) == -1) {
					printf("Failed to set xattr 'user.found' to '%s' for '%s': %m\n", tstamp, event_path);
				}
				printf("%s: %s moved in, size: %ld bytes\n", event_string, event_path, st.st_size);
				free(tstamp);
				free(event_path);
*/

			} else {
//				if (event->mask & IN_DELETE_SELF) {

//kill_watchent(void
//
//				if ( IN_DELETE_SELF
				printf("Got an event for %s, but not sure what to do with it\n", wd_event_path);
			}
		}
	}
}

int main(int argc, char *argv[]) {
	char buf;
//	int fd, i, poll_num;
	int i, poll_num;
	nfds_t nfds;
	struct pollfd fds[2];
//	struct stat st;
	char *path;

	if (argc < 2) {
		printf("Usage: %s PATH [PATH ...]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	struct wd_info_struct *wd_info = malloc(sizeof(struct wd_info_struct));

	/* get an fd to inotify */
	if ((wd_info->inotify_fd = inotify_init1(IN_NONBLOCK)) == -1)
		exit_fail("inotify_init: %m");

	wd_info->tree_root = NULL;

	wd_info->active_wds = 0;

	for (i = 1 ; i < argc ; i++) {
		path = canonicalize_file_name(argv[i]);
		add_watches_recursive(wd_info, path);
		free(path);
	}

printf("tree:\n");

twalk(wd_info->tree_root, walk_entry2);



printf("....\n");

printf("tree size = %d\n", get_tree_size(wd_info));



           /* Mark directories for events
              - file was opened
              - file was closed */

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
			exit_fail("poll error: %m");
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

//	free(wd);
	return EXIT_SUCCESS;
}
