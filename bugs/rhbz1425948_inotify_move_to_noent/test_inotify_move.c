/*
	Frank Sorenson <sorenson@redhat.com>
	Red Hat, 2017

	program to listen for inotify MOVE_TO event
	with stat() of the new file returning ENOENT
	or listen for 

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



#define KiB (1024ULL)
#define BUF_SIZE (32ULL * KiB)
#define MAX_EVENT_STRLEN (4ULL * KiB)

/* hitting the thresh is considered over */
#define TSTAMP_THRESH_SEC  (1ULL)
#define TSTAMP_THRESH_NSEC (0ULL)


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
	struct wd_path_struct *wd_paths;
};

int tree_find_path(struct wd_info_struct *wd_info, const char *path) {
	const struct watchent *found_watchent = NULL;

	void walk_tree_find_path(const void *p, VISIT x, int level) {
		const struct watchent *tmp = p;

		if ((x == leaf || x == postorder) && (!found_watchent)) {
			if (!strncmp(path, tmp->path, strlen(path)))
				found_watchent = tmp;
		}
	}
	twalk(wd_info->tree_root, walk_tree_find_path);
	if (found_watchent)
		return found_watchent->wd;
	return -1;
}

int get_tree_size(struct wd_info_struct *wd_info) {
	int tree_size = 0;
	void walk_tree_size(const void *p, VISIT x, int level) {
		if (x == leaf || x == postorder)
			tree_size++;
	}
	twalk(wd_info->tree_root, walk_tree_size);
	return tree_size;
}

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

struct watchent *find_watchent(struct wd_info_struct *wd_info, int wd) {
	struct watchent *tmp_watchent;
	struct watchent *ret;

	tmp_watchent = new_watchent(wd, 0);
	ret = tfind(tmp_watchent, &wd_info->tree_root, compare_wd_entries);
	kill_watchent(tmp_watchent);
	return ret;
}

void ignore_watchent(struct wd_info_struct *wd_info, int wd) {
	struct watchent *tmp_watchent;

	tmp_watchent = new_watchent(wd, 0);
	tdelete(tmp_watchent, &wd_info->tree_root, compare_wd_entries);
	kill_watchent(tmp_watchent);

//	printf("tree size now %d\n", get_tree_size(wd_info));
}

void walk_entry(const void *p, VISIT x,int level) {
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

struct timespec ts_elapsed(const struct timespec ts1, const struct timespec ts2) {
	struct timespec ret, a, b;
	if ((ts1.tv_sec > ts2.tv_sec) ||
		((ts1.tv_sec == ts2.tv_sec) && (ts1.tv_nsec >= ts2.tv_nsec))) {
		a = ts1; b = ts2;
	} else {
		a = ts2; b = ts1;
	}
	ret.tv_sec = a.tv_sec - b.tv_sec - 1;
	ret.tv_nsec = a.tv_nsec - b.tv_nsec + 1000000000;
	while (ret.tv_nsec >= 1000000000) {
		ret.tv_sec ++;
		ret.tv_nsec -= 1000000000;
	}
	return ret;
}

int ts_ge_ts(const struct timespec ts1, const struct timespec ts2) {
	if ((ts1.tv_sec > ts2.tv_sec) ||
		((ts1.tv_sec == ts2.tv_sec) &&
		 (ts1.tv_nsec >= ts2.tv_nsec)))
		return 1;
	return 0;
}
int ts_gt_ts(const struct timespec ts1, const struct timespec ts2) {
	if ((ts1.tv_sec > ts2.tv_sec) ||
		((ts1.tv_sec == ts2.tv_sec) &&
		 (ts1.tv_nsec > ts2.tv_nsec)))
		return 1;
	return 0;
}

int ts_over_thresh(const struct timespec ts) {
	struct timespec thresh_ts =
		{ .tv_sec = TSTAMP_THRESH_SEC, .tv_nsec = TSTAMP_THRESH_NSEC };
	return ts_ge_ts(ts, thresh_ts);
}

int ts_diff_over_thresh(const struct timespec ts1, const struct timespec ts2) {
	struct timespec elapsed;

	elapsed = ts_elapsed(ts1, ts2);
	return ts_over_thresh(elapsed);
}

struct timespec tstamp_to_timespec(const char *tstamp) {
	struct timespec ret;
	char *p;

	ret.tv_sec = strtol(tstamp, &p, 10);
	p++;
	ret.tv_nsec = strtol(p, NULL, 10);

	return ret;
}

struct timespec tstamp_to_timespec_old(const char *tstamp) {
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

char *create_tstamp(const struct timespec *ts) {
	char *tstamp;
	asprintf(&tstamp, "%ld.%09ld", ts->tv_sec, ts->tv_nsec);
	return tstamp;
}

char *create_tstamp_old(const struct timespec *ts) {
	struct tm tm_info;
	char time_buffer[32];
	char tzbuf[8];
	char *tstamp;

	localtime_r(&ts->tv_sec, &tm_info);
	strftime(time_buffer, 32, "%F %T", &tm_info);
	strftime(tzbuf, 8, "%Z", &tm_info);
	asprintf(&tstamp, "%s.%09ld %s", time_buffer, ts->tv_nsec, tzbuf);

	return tstamp;
}
char *create_now_tstamp(void) {
	struct timespec now_ts;
	clock_gettime(CLOCK_REALTIME, &now_ts);
	return create_tstamp(&now_ts);
}

char *create_stat_tstamp(const char *path) {
	struct stat st;

	stat(path, &st);
	return create_tstamp(&st.st_mtim);
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



void add_watch_dir(struct wd_info_struct *wd_info, char *path) {
	int wd;
	struct watchent *new_ent;

	printf("Adding watch for dir: %s\n", path);
	wd = inotify_add_watch(wd_info->inotify_fd, path, IN_MOVED_TO | IN_ATTRIB | IN_CREATE | IN_IGNORED | IN_DELETE);
	new_ent = new_watchent(wd, path);
	tsearch(new_ent, &wd_info->tree_root, compare_wd_entries);

	printf("tree size now %d\n", get_tree_size(wd_info));
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
//	ret = inotifytools_snprintf(event_string, MAX_EVENT_STRLEN, event, "%w: '%f' had events: %e");
	ret = inotifytools_snprintf(event_string, MAX_EVENT_STRLEN, (struct inotify_event *)event, "%e");
	if (ret != -1)
		return event_string;
	free(event_string);
	return strdup("UNKNOWN EVENT");
}

void do_file_work(char *path, struct stat *st) {
	/* here is where we'd do some work/actions for each file */

	struct timespec ts;

	ts.tv_sec = 0;
	ts.tv_nsec = 500000;

	nanosleep(&ts, NULL);
}

void update_xattr(const char *path, struct timespec *ts) {
	char *tstamp;

	tstamp = create_tstamp(ts);
	if ((setxattr(path, FOUND_XATTR, tstamp, strlen(tstamp) + 1, 0)) == -1)
		printf("WARNING: Failed to set xattr '" FOUND_XATTR "' to '%s' for '%s': %m\n", tstamp, path);
	free(tstamp);
}

void process_file(struct wd_info_struct *wd_info, char *path) {
	/* startup behavior: */
	/* check whether it has an extended attribute */

//	char *event_string = "UNKNOWN";
	char *xattr_string = NULL;
	struct stat st;
	struct timespec now_ts;
	ssize_t len;

	if (stat(path, &st) == -1) {
		printf("Error calling stat() on '%s': %m\n", path);
		return;
	}
	clock_gettime(CLOCK_REALTIME, &now_ts);

	len = getxattr(path, FOUND_XATTR, xattr_string, 0);
	if (len > 0) {
		xattr_string = malloc(len);
		len = getxattr(path, FOUND_XATTR, xattr_string, len);
//		printf("%s already has '" FOUND_XATTR "' = '%s'\n", path, xattr_string);

		struct timespec ts;
		struct timespec elapsed;
		ts = tstamp_to_timespec(xattr_string);
		elapsed = ts_elapsed(ts, st.st_mtim);

		if (ts_over_thresh(elapsed)) {
//		if (ts_diff_over_thresh(ts, st.st_mtim)) {
//			update_xattr(path, st.st_mtim);
			update_xattr(path, &st.st_mtim);
			printf("WARNING: file processed previously, but timestamp is out of threshold: '%s'\n", path);
			printf("\tfile time: %ld.%09ld, timestamp: %ld.%09ld, %s more recent by %ld.%09ld sec\n",
				st.st_mtim.tv_sec, st.st_mtim.tv_nsec, ts.tv_sec, ts.tv_nsec,
				ts_gt_ts(ts, st.st_mtim) ? "timestamp" : "file time",
				elapsed.tv_sec, elapsed.tv_nsec);
			do_file_work(path, &st);
		} /* otherwise, the timestamp is within threshold */
		free(xattr_string);
	} else if (len < 0 && errno == ENOTSUP) /* kinda pointless to test on this filesystem, no? */
		exit_fail("Filesystem does not appear to support xattrs\n");
	else {
		if (ts_diff_over_thresh(now_ts, st.st_mtim))
			printf("WARNING: file not processed within threshold: '%s'\n", path);
		update_xattr(path, &st.st_mtim);
		do_file_work(path, &st);
	}
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
//		add_watch_file(wd_info, path);
		process_file(wd_info, path);
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
//	struct watchent *tmp_watchent;
	struct watchent *tree_watchent;
	uint32_t handled_events = 0;

	for (;;) {
		len = read(wd_info->inotify_fd, buf, sizeof(buf));
		if (len == -1 && errno != EAGAIN)
			exit_fail("error reading from inotify_fd: %m\n");

		if (len <= 0)
			break;
		for (ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
			event = (const struct inotify_event *) ptr;
			handled_events = 0;
//			progress_counter(counter, ".");

			event_string = create_event_string(event);

			tree_watchent = find_watchent(wd_info, event->wd);

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


			if (*event->name == '\0') {
				event_path = strdup(wd_event_path);
			} else {
				asprintf(&event_path, "%s/%s", wd_event_path, event->name);
			}
printf("got %s event: %s (path '%s')\n", (event->mask & IN_ISDIR) ? "DIRECTORY" : "FILE", event_string, event_path);
printf("\twatch descriptor's path: %s, event->name: %s\n", wd_event_path, event->name);

			if (event->mask & IN_ISDIR) {
				handled_events |= IN_ISDIR;
				if (event->mask & IN_CREATE) {
					add_watches_recursive(wd_info, event_path);
					handled_events |= IN_CREATE;
				}
				if (event->mask & IN_MOVED_TO) { /* directory moved in */
					add_watches_recursive(wd_info, event_path);
					handled_events |= IN_MOVED_TO;
				}
				if (event->mask & IN_DELETE) /* directory inside directory was removed; subdir should generate events--we can ignore */
					handled_events |= IN_DELETE;

				if (event->mask & IN_ATTRIB)
					handled_events |= IN_ATTRIB;
				if (event->mask & IN_OPEN)
					handled_events |= IN_OPEN;
				if (event->mask & IN_MOVED_FROM) /* wait for the IN_IGNORED event before killing the wd */
					handled_events |= IN_MOVED_FROM;
				if (event->mask & IN_DELETE_SELF) /* wait for the IN_IGNORED event before killing the wd */
					handled_events |= IN_DELETE_SELF;
				if (event->mask & IN_IGNORED) {
					ignore_watchent(wd_info, event->wd);
					handled_events |= IN_IGNORED;
				}

			} else { /* event for a file, rather than a dir */
				if (event->mask & IN_DELETE_SELF) { /* stupid thing shows up as a file event */
				/* IN_DELETE_SELF -- supposed to only occur for a watched item, and since we're only watching dirs... */
					printf("\t***** directory '%s' deleted *****\n", event_path);
				}

				if (event->mask & IN_IGNORED) {
					printf("\t***** directory '%s' ignored *****\n", event_path);
					ignore_watchent(wd_info, event->wd);

					handled_events |= IN_IGNORED;
				}
				if (event->mask & IN_MOVED_TO) { /* file moved in */
					process_file(wd_info, event_path);
					handled_events |= IN_MOVED_TO;
				}
				if (event->mask & IN_ATTRIB) { /* file touched, etc. */
					process_file(wd_info, event_path);
					handled_events |= IN_ATTRIB;
				}

				if (event->mask & IN_DELETE) /* file was deleted */
					handled_events |= IN_DELETE;

				if (event->mask & IN_OPEN)
					handled_events |= IN_OPEN; /* process when closing, if opened for write */
				if (event->mask & IN_CREATE) /* we'll process when closing */
					handled_events |= IN_CREATE;
				if (event->mask & IN_MODIFY) /* file was modified - reprocess when closing */
					handled_events |= IN_MODIFY;
				if (event->mask & IN_CLOSE_WRITE) { /* we'll reprocess */
					process_file(wd_info, event_path);
					handled_events |= IN_CLOSE_WRITE;
				}
				if (event->mask & IN_CLOSE_NOWRITE) /* nothing to do */
					handled_events |= IN_CLOSE_NOWRITE;


			}

//			printf("\t'%s' for '%s': event->mask: 0x%08x, handled_events: 0x%08x\n",
//				event_string, event_path, event->mask, handled_events);
			if (event->mask != handled_events)
				printf("\t*** WARNING *** unhandled events:\n"
					"\t'%s' for '%s': event->mask: 0x%08x, handled_events: 0x%08x\n",
					event_string, event_path, event->mask, handled_events);



		}
		free(event_path);
		free(event_string);
	}
}

int main(int argc, char *argv[]) {
	char buf;
	int i, poll_num;
	nfds_t nfds;
	struct pollfd fds[2];
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

	inotifytools_initialize();
	for (i = 1 ; i < argc ; i++) {
		path = canonicalize_file_name(argv[i]);
		add_watches_recursive(wd_info, path);
		free(path);
	}

	/* display the tree */
//	printf("tree:\n");
//	twalk(wd_info->tree_root, walk_entry);
//	printf("....\n");
//	printf("tree size = %d\n", get_tree_size(wd_info));


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
