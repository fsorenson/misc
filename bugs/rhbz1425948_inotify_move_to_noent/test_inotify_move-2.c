/*
	Frank Sorenson <sorenson@redhat.com>
	Red Hat, 2017

	program to listen for inotify MOVE_TO and other events

	usage: test_inotify_move directory_to_monitor

	# gcc -Wall test_inotify_move.c -o test_inotify_move -ggdb3 -l inotifytools 2>&1

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

#define WATCH_FILES 0


//#define DIR_WATCH_EVENTS (IN_MOVED_TO | IN_ATTRIB | IN_CREATE | IN_IGNORED | IN_DELETE)
#define DIR_WATCH_EVENTS (IN_ALL_EVENTS)
#define DIR_DONTCARE_EVENTS (IN_ACCESS|IN_ATTRIB|IN_OPEN|IN_CLOSE_WRITE|IN_CLOSE_NOWRITE)
#define FILE_DONTCARE_EVENTS (IN_ACCESS|IN_DELETE|IN_OPEN|IN_CREATE|IN_MODIFY|IN_CLOSE_NOWRITE)


#define KiB (1024ULL)
#define BUF_SIZE (32ULL * KiB)
#define MAX_EVENT_STRLEN (4ULL * KiB)
#define INOTIFY_BUFFER_SIZE (8ULL * KiB)

#define QUIET 1

#define exit_fail(args...) do { \
	printf("Error %d: %s - ", errno, strerror(errno)); \
	printf(args); exit(EXIT_FAILURE); } while (0)


#define unlikely(x)     __builtin_expect((x),0)

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
};
static int interrupted = 0;


void debug_dump(const void *p, VISIT x,int level) {
	struct watchent *watchent = *(struct watchent **)p;

	if (x == leaf || x == postorder) {
		printf("<%d>Walk on node %p: %s %u %s  \n",
			level,
			watchent,
			x == preorder?"preorder":
			x == postorder?"postorder":
			x == endorder?"endorder":
			x == leaf?"leaf":
			"unknown",
			watchent->wd, watchent->path);
	}
}

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
	struct watchent tmp_watchent;
	struct watchent *ret;

	tmp_watchent.wd = wd;
	ret = tfind(&tmp_watchent, &wd_info->tree_root, compare_wd_entries);
	return ret;
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

char *create_tstamp(const struct timespec *ts) {
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

enum entry_added_cause { ENTRY_ADDED_CMDLINE, ENTRY_ADDED_EVENT, ENTRY_ADDED_RECURSIVE };

static char *entry_added_cause_string[] = {
	[ENTRY_ADDED_CMDLINE] = "command line",
	[ENTRY_ADDED_EVENT] = "event",
	[ENTRY_ADDED_RECURSIVE] = "recursive"
};
enum watchent_type { WATCHENT_TYPE_DIR, WATCHENT_TYPE_FILE };
static char *watchent_type_string[] = {
	[WATCHENT_TYPE_DIR] = "dir",
	[WATCHENT_TYPE_FILE] = "file"
};

void add_watch(struct wd_info_struct *wd_info, char *path, enum watchent_type type, enum entry_added_cause added_cause) {
	int wd;
	struct watchent *new_ent;
	struct watchent *ret, *retptr;

	wd = inotify_add_watch(wd_info->inotify_fd, path, DIR_WATCH_EVENTS);
	new_ent = new_watchent(wd, path);
//	ret = tfind(new_ent, &wd_info->tree_root, compare_wd_entries);
	retptr = tsearch(new_ent, &wd_info->tree_root, compare_wd_entries);

	if (retptr == NULL) {
		printf("unable to add node\n");
		exit(1);
	}
	ret = *(struct watchent **)retptr;
	if (ret != new_ent) { /* already exists */
		kill_watchent(new_ent);
	} else {
		printf("added %s watchent (%s): %d -> '%s': %p\n",
			watchent_type_string[type],
			entry_added_cause_string[added_cause],
			ret->wd, ret->path, ret);
		wd_info->active_wds++;
	}
#if 0
	if (ret == NULL) { /* new entry */
		printf("Adding watch (wd = %d) for %s (%s): %s\n", wd,
			watchent_type_string[type],
			entry_added_cause_string[added_cause], path);
		printf("new_ent = %p, new_ent->wd=%d, new_ent->path='%s'\n", new_ent, new_ent->wd, new_ent->path);
		ret = tsearch(new_ent, &wd_info->tree_root, compare_wd_entries);
		printf("added watchent = %p (%d -> %s)\n", ret, (*ret)->wd, (*ret)->path);

//		printf("looks like a new entry\n");
//		printf("tree size now %d\n", get_tree_size(wd_info));
	} else
		kill_watchent(new_ent);
#endif
}
void ignore_watchent(struct wd_info_struct *wd_info, int wd) {
	struct watchent *tmp_watchent;
	struct watchent *ret;

	tmp_watchent = new_watchent(wd, 0);
	ret = tdelete(&tmp_watchent, &wd_info->tree_root, compare_wd_entries);
	kill_watchent(tmp_watchent);
}
void ignore_watchent_2(struct wd_info_struct *wd_info, int wd) {
	struct watchent *tmp_watchent;
	struct watchent *keep_ptr;
	void *ret;
	struct watchent *old_ent;
	struct watchent *foo;

	tmp_watchent = new_watchent(wd, 0);

	ret = tfind(tmp_watchent, &wd_info->tree_root, compare_wd_entries);
	if (ret) {
		keep_ptr = *(struct watchent **)ret;
		ret = tdelete(tmp_watchent, &wd_info->tree_root, compare_wd_entries);
		if (ret) {
			old_ent = *(struct watchent **)ret;
//			printf("tdelete returned parent: %p %d -> '%s'\n", old_ent, old_ent->wd, old_ent->path);
		} else {
//			printf("tdelete returned NULL... tree empty\n");
			wd_info->tree_root = NULL;
		}
		kill_watchent(keep_ptr);
		wd_info->active_wds--;
	}
	kill_watchent(tmp_watchent);

#if 0
	foo = *ret;

	printf("tree walk prior to deleting %p (%d -> %s)\n", *ret, (*ret)->wd, (*ret)->path);
	twalk(wd_info->tree_root, debug_dump);
		fflush(stdout);
	if (ret) {
		printf("deleting watchent ret=%p, *ret=%p, foo=%p\n", ret, *ret, foo);
		fflush(stdout);
//		ret2 = tdelete(&tmp_watchent, &wd_info->tree_root, compare_wd_entries);
//		ret2 = tdelete(&tmp_watchent, &wd_info->tree_root, compare_wd_entries);
//		ret2 = tdelete(ret, &wd_info->tree_root, compare_wd_entries);
		ret2 = tdelete(*ret, &wd_info->tree_root, compare_wd_entries);
		printf("watchent removed from tree = %p (ret2 = %p), foo=%p\n", *ret, ret2, foo);
		fflush(stdout);
//		kill_watchent(*ret);
		kill_watchent(foo);
//		printf("deleted watchent = %p (%d -> %s)\n", *ret, (*ret)->wd, (*ret)->path);
//		fflush(stdout);
	}
//	printf("tree walk after deleting %p (%d -> %s)\n", ret, (*ret)->wd, (*ret)->path);
	printf("tree walk after deleting %p\n", foo);
	twalk(wd_info->tree_root, debug_dump);
#endif
}



void do_file_work(char *path, struct stat *st) {
	/* here is where we'd do some work/actions for each file */

	struct timespec ts;

	ts.tv_sec = 0;
	ts.tv_nsec = 500000;

	nanosleep(&ts, NULL);
}

struct val_str_pair {
	long val;
	const char *string;
};
#define N(a) { .val = IN_##a, .string = #a }
static const struct val_str_pair event_string_pair[] = {
	N(ACCESS),
	N(MODIFY),
	N(ATTRIB),
	N(CLOSE_WRITE),
	N(CLOSE_NOWRITE),
	N(OPEN),
	N(MOVED_FROM),
	N(MOVED_TO),
	N(CREATE),
	N(DELETE_SELF),
	N(DELETE),
	N(UNMOUNT),
	N(Q_OVERFLOW),
	N(IGNORED),
//	N(CLOSE),
	N(MOVE_SELF),
	N(ISDIR),
	N(ONESHOT)
};
static const int max_event_string_pair = sizeof(event_string_pair)/sizeof(event_string_pair[0]);
#undef N

char *create_event_string(const struct inotify_event *event) {
	char *event_string;
//	int ret;
	char sep = '|';
	int i;

	event_string = calloc(MAX_EVENT_STRLEN+1, sizeof(char));
	for (i = 0 ; i < max_event_string_pair ; i++) {
		if (event->mask & event_string_pair[i].val) {
			strcat(event_string, event_string_pair[i].string);
			event_string[strlen(event_string)] = sep;
		}
	}
	if (strlen(event_string)) {
		event_string[strlen(event_string) - 1] = '\0';
	}
	return event_string;


//	ret = inotifytools_snprintf(event_string, MAX_EVENT_STRLEN, event, "%w: '%f' had events: %e");
#if 0
	ret = inotifytools_snprintf(event_string, MAX_EVENT_STRLEN, (struct inotify_event *)event, "%e");
	if (ret != -1)
		return event_string;
	free(event_string);
	return strdup("UNKNOWN EVENT");
#endif
}

void process_file(struct wd_info_struct *wd_info, char *path) {
	/* do nothing */
}

void add_watches_recursive(struct wd_info_struct *wd_info, char *path, enum entry_added_cause added_cause) {
	/* add self directory */
	/* iterate children, recurse for each dir */
	int dir_fd;
	char buf[BUF_SIZE];
	char *bpos;
	int nread;
	struct linux_dirent64 *temp_de;
	struct stat st;

	if (stat(path, &st) == -1) {
		printf("could not add watch for file/directory '%s', stat() failed with: %m\n", path);
		return;
	}
	if (S_ISREG(st.st_mode)) {
#if WATCH_FILES
		add_watch(wd_info, path, WATCHENT_TYPE_FILE, added_cause);
#endif
		process_file(wd_info, path);
		return;
	}
	add_watch(wd_info, path, WATCHENT_TYPE_DIR, added_cause);

        if ((dir_fd = open(path, O_RDONLY | O_DIRECTORY)) == -1) {
		printf("could not open directory '%s' to add watches recursively: %m\n",
			path);
	}
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
					if (fstatat(dir_fd, temp_de->d_name, &st, AT_SYMLINK_NOFOLLOW) == -1) {
						printf("could not add watch for file/directory '%s', fstatat() failed with: %m\n", path);
						break;
					}
					if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
						break;
				;;
				case DT_DIR:
				case DT_REG: {
					char *new_path;
					asprintf(&new_path, "%s/%s", path, temp_de->d_name);
					add_watches_recursive(wd_info, new_path, ENTRY_ADDED_RECURSIVE);
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
	char *event_string;
//	struct watchent *tmp_watchent;
	struct watchent *tree_watchent;
	uint32_t handled_events = 0;

	for (;;) {
		len = read(wd_info->inotify_fd, buf, sizeof(buf));
		if (len == -1 && errno != EAGAIN)
			exit_fail("error reading from inotify_fd: %m\n");

		if (len <= 0)
			break;
		buf[len] = '\0'; /* may not be null-terminated */

		for (ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
			event = (const struct inotify_event *) ptr;
			handled_events = 0;

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



			if (event->len == 0)
				event_path = strdup(wd_event_path);
			else
				asprintf(&event_path, "%s/%s", wd_event_path, event->name);

printf("%s event: %s (path '%s')\n", (event->mask & IN_ISDIR) ? "DIRECTORY" : "FILE", event_string, event_path);
//free(event_string);

#if 0
if (event->len) {
printf("\twatch descriptor's path: '%s', event->name: '%s'\n", wd_event_path, event->name);
} else {
printf("\twatch descriptor's path: '%s'\n", wd_event_path);
}
#endif

			if (event->mask & IN_ISDIR) {
				handled_events |= IN_ISDIR;

				if (event->mask & (IN_CREATE|IN_MOVED_TO)) {
//printf("recursively adding watches for '%s'\n", event_path);
					add_watches_recursive(wd_info, event_path, ENTRY_ADDED_EVENT);
					handled_events |= (event->mask & (IN_CREATE|IN_MOVED_TO));
				}
				if (event->mask & IN_DELETE) { /* directory inside directory was removed; subdir should generate events--we can ignore */
//					printf("\t***** directory '%s' deleted *****\n", event_path);
					handled_events |= IN_DELETE;
				}

				if (event->mask & IN_MOVED_FROM) /* wait for the IN_IGNORED event before killing the wd */
					handled_events |= IN_MOVED_FROM;
				if (event->mask & IN_DELETE_SELF) /* wait for the IN_IGNORED event before killing the wd */
					handled_events |= IN_DELETE_SELF;

				if (event->mask & IN_IGNORED) {
					ignore_watchent_2(wd_info, event->wd);
					handled_events |= IN_IGNORED;
				}
				handled_events |= (DIR_DONTCARE_EVENTS & event->mask);

			} else { /* event for a file, rather than a dir */
				if (event->mask & IN_DELETE_SELF) { /* stupid thing shows up as a file event */
				/* IN_DELETE_SELF -- supposed to only occur for a watched item, and since we're only watching dirs... */
					printf("\t***** directory '%s' deleted *****\n", event_path);
					handled_events |= IN_DELETE_SELF;
				}

				if (event->mask & IN_IGNORED) {
					printf("\t***** directory '%s' ignored *****\n", event_path);
					ignore_watchent_2(wd_info, event->wd);

					handled_events |= IN_IGNORED;
				}

				if (event->mask & (IN_MOVED_TO|IN_ATTRIB|IN_CLOSE_WRITE)) {
					/* file moved in, touched, closed after possible write */
					process_file(wd_info, event_path);
					handled_events |= (event->mask & (IN_MOVED_TO|IN_ATTRIB|IN_CLOSE_WRITE));
				}
				handled_events |= (FILE_DONTCARE_EVENTS & event->mask);
			}
//			printf("\t'%s' for '%s': event->mask: 0x%08x, handled_events: 0x%08x\n",
//				event_string, event_path, event->mask, handled_events);
			if (event->mask != handled_events)
				printf("\t*** WARNING *** unhandled events:\n"
					"\t'%s' for '%s': event->mask: 0x%08x, handled_events: 0x%08x\n",
					event_string, event_path, event->mask, handled_events);
		free(event_path);
		free(event_string);
		}
//		free(event_path);
//		free(event_string);
	}
}

void handle_interrupt(int sig) {
	interrupted++;
}

int main(int argc, char *argv[]) {
	int i, poll_num;
	nfds_t nfds;
	struct pollfd fds[1];
	struct sigaction sa;
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
		if (path) {
			add_watches_recursive(wd_info, path, ENTRY_ADDED_CMDLINE);
			free(path);
		} else {
			printf("Unable to watch path '%s' given on command line (%s): %m\n",
				path, argv[i]);
		}
	}
	if (wd_info->active_wds < 1) {
		printf ("could not watch any paths\n");
		return EXIT_FAILURE;
	}
	twalk(wd_info->tree_root, debug_dump);



	/* Wait for events, empty watch tree, or interrupt */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &handle_interrupt;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* Prepare for polling inotify input */
	nfds = 1;
	fds[0].fd = wd_info->inotify_fd;
	fds[0].events = POLLIN;

	printf("Listening for events.\n");
	while (wd_info->active_wds > 0 && !interrupted) {
		poll_num = poll(fds, nfds, -1);
		if (poll_num == -1) {
			if (errno == EINTR)
				continue;
			exit_fail("poll error: %m");
		}

		if (poll_num > 0) {
			/* Inotify events are available */
			if (fds[1].revents & POLLIN)
				handle_events(wd_info);
		}
	}
	if (interrupted) {
		printf("exiting on interrupt.  current watch tree:\n");
		twalk(wd_info->tree_root, debug_dump);
	}
	if (wd_info->active_wds < 1) {
		printf("exiting with no remaining watched paths\n");
	}

	/* Close inotify file descriptor */
	close(wd_info->inotify_fd);
	tdestroy(wd_info->tree_root, kill_watchent);
	free(wd_info);

	return EXIT_SUCCESS;
}
