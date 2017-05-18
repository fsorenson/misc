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
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>
#include <errno.h>
#include <syscall.h>
#include <dirent.h>

#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

// binary trees
#include <search.h>

#define WATCH_FILES 0


//#define DIR_WATCH_EVENTS (IN_MOVED_TO | IN_ATTRIB | IN_CREATE | IN_IGNORED | IN_DELETE)
#define DIR_WATCH_EVENTS (IN_ALL_EVENTS)
#define DIR_SILENCE_EVENTS (IN_ACCESS|IN_ATTRIB|IN_OPEN|IN_CLOSE_WRITE|IN_CLOSE_NOWRITE)
#define FILE_DONTCARE_EVENTS (IN_ACCESS|IN_DELETE|IN_OPEN|IN_CREATE|IN_MODIFY|IN_CLOSE_NOWRITE)

static int dontcare_masks[] = {
	IN_ACCESS|IN_ISDIR,
	IN_OPEN|IN_ISDIR,
	IN_CLOSE_NOWRITE|IN_ISDIR
};
static const int dontcare_masks_count = sizeof(dontcare_masks)/sizeof(dontcare_masks[0]);


#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define BUF_SIZE (32ULL * KiB)
#define MAX_EVENT_STRLEN (4ULL * KiB)
#define INOTIFY_BUFFER_SIZE (4ULL * KiB)


#define DEFAULT_LOG_ROTATE_SIZE (200ULL * MiB)
#define DEFAULT_LOG_DIR "/tmp/inotify_tmp"
#define DEFAULT_LOG_PATTERN "log.%d"

#define QUIET 1


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
	void *path_tree_root;
	int active_wds;
	int inotify_fd;
	int interrupted;

	int stdout_is_tty;
	char *stdout_device;
	int stdout_fd;
	int output_fd;
	int log_dir_fd;
	char *log_dir;

	unsigned long total_bytes;
	unsigned long log_bytes;
	int log_filenum;
	unsigned long log_rotate_size;

	char *log_basename;
	char *log_pattern;

	char *log_filename;
};
static struct wd_info_struct *wd_info;


int mkdir_r(char *path) {
	char *parent_path;
	struct stat st;
	char *tmp;
	int ret;

re_stat:
	if (stat(path, &st) == -1) {
		if (errno == ENOTDIR)
			return -ENOTDIR;

		if (errno == ENOENT) {
			tmp = strdup(path);
			parent_path = dirname(tmp);

			ret = mkdir_r(parent_path);
			free(tmp);
			if (ret < 0)
				return ret;
			ret = mkdir(path, 0755);
			return -ret;
		}
		goto re_stat;
	}
	if (! S_ISDIR(st.st_mode))
		return -ENOTDIR;

	return 0;
}

void open_log(void) {
	asprintf(&wd_info->log_filename, wd_info->log_pattern, wd_info->log_filenum);

	if ((wd_info->output_fd = openat(wd_info->log_dir_fd, wd_info->log_filename, O_CREAT | O_TRUNC | O_WRONLY, 0666)) < 0) {
		printf("ERROR: unable to open logfile '%s/%s': %m\n",
			wd_info->log_dir, wd_info->log_filename);
		exit(EXIT_FAILURE);
	}
	wd_info->log_bytes = 0;
}
void close_log(void) {
	close(wd_info->output_fd);
}
void compress_log(char *logfile, int wait) {
	pid_t cpid = 0;
	char *argv[] = { "/usr/bin/xz", "-f", NULL, NULL, NULL, NULL };
	char *env[] = { NULL };

	cpid = fork();
	if (cpid && !wait) /* parent process, and not waiting */
		return;

	if (!cpid) { /* child process... exec the compressor */
		argv[2] = logfile;
		execve(argv[0], argv, env);
		printf("ERROR: unable to execute compressor ('%s') for log file '%s': %m\n",
			argv[0], logfile);
		exit(EXIT_FAILURE);
	}

	if (wait)
		waitpid(cpid, NULL, 0); /* could use some error handling, etc. */
}
void rotate_log(void) {
	char *old_log;

	asprintf(&old_log, "%s/%s", wd_info->log_dir, wd_info->log_filename);
	close_log();
	wd_info->log_filenum++;
	free(wd_info->log_filename);

	compress_log(old_log, 0);
	open_log();
}

static int check_rotate(void) {
	if (wd_info->log_bytes >= wd_info->log_rotate_size) {
		rotate_log();
		return 1;
	}
	return 0;
}

static int init_logging(char *log_dir) {
	int ret;

	wd_info->total_bytes = 0;
	wd_info->log_bytes = 0;
	wd_info->log_filenum = 0;

	wd_info->log_rotate_size = DEFAULT_LOG_ROTATE_SIZE;
//	wd_info->log_dir = DEFAULT_LOG_DIR;
	wd_info->log_dir = log_dir;
	wd_info->log_pattern = DEFAULT_LOG_PATTERN;

	ret = mkdir_r(wd_info->log_dir);
	if (ret < 0) {
		printf("unable to create log directory '%s'\n", wd_info->log_dir);
		return -ENOTDIR;
	}
	if ((wd_info->log_dir_fd = open(wd_info->log_dir, O_RDONLY|O_DIRECTORY)) < 0) {
		printf("ERROR: unable to open log directory '%s': %m\n",
			wd_info->log_dir);
		return -errno;
	}
	open_log();
	return 0;
}

#define __output(args...) do { \
	int bytes = dprintf(wd_info->output_fd, args); \
	wd_info->log_bytes += bytes; \
	wd_info->total_bytes += bytes; \
} while (0)


static char tstamp_buf[30] = { 0 };
#define out_tstamp() do { \
	struct timespec ts; \
	struct tm tm_info; \
	clock_gettime(CLOCK_REALTIME, &ts); \
	localtime_r(&ts.tv_sec, &tm_info); \
	strftime(tstamp_buf, sizeof(tstamp_buf), "%F %T", &tm_info); \
	snprintf(tstamp_buf + 19, 10, ".%06ld", ts.tv_nsec / 1000); \
	__output("%s ", tstamp_buf); \
} while (0)
#define output(args...) do { \
	out_tstamp(); \
	__output(args); \
	check_rotate(); \
} while (0)

#define exit_fail(args...) do { \
	output("Error %d: %s - ", errno, strerror(errno)); \
	output(args); exit(EXIT_FAILURE); } while (0)

#define unlikely(x)     __builtin_expect((x),0)


#define event_compare(mask, flags) ((mask & (flags)) == (flags))


void handle_interrupt(int sig) {
	wd_info->interrupted++;
}

void dump_watch_tree(const void *p, VISIT x,int level) {
	struct watchent *watchent = *(struct watchent **)p;

	if (x == leaf || x == postorder) {
		output("wd: %d - %s\n",
			watchent->wd, watchent->path);
	}
}
void display_tree(void) {
	twalk(wd_info->tree_root, dump_watch_tree);
}
void debug_dump(const void *p, VISIT x,int level) {
	struct watchent *watchent = *(struct watchent **)p;

	if (x == leaf || x == postorder) {
		output("<%d>Walk on node %p: %s %u %s  \n",
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

int do_init(void) {
	char buf[PATH_MAX];
	struct sigaction sa;

	wd_info = malloc(sizeof(struct wd_info_struct));

	wd_info->stdout_fd = fileno(stdout);

	/* should change once logging is configured */
	wd_info->output_fd = wd_info->stdout_fd;

	/* not sure these are important, but what the heck */
	ttyname_r(wd_info->stdout_fd, buf, PATH_MAX);
	wd_info->stdout_device = strdup(buf);
	wd_info->stdout_is_tty = isatty(wd_info->stdout_fd);


	/* get an fd to inotify */
	if ((wd_info->inotify_fd = inotify_init1(IN_NONBLOCK)) == -1)
		exit_fail("inotify_init: %m");

	wd_info->tree_root = NULL;
	wd_info->path_tree_root = NULL;
	wd_info->active_wds = 0;
	wd_info->interrupted = 0;
	if (init_logging(DEFAULT_LOG_DIR) < 0) {
		printf("unable to configure logging to '%s'\n", DEFAULT_LOG_DIR);
		return EXIT_FAILURE;
	}
	printf("Initialized logging to '%s'\n", DEFAULT_LOG_DIR);

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &handle_interrupt;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	return 0;
}

int tree_find_path(const char *path) {
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

int get_tree_size(void) {
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
int compare_entries_by_path(const void *p1, const void *p2) {
	const struct watchent *entry1 = p1;
	const struct watchent *entry2 = p2;
	return strcmp(entry1->path, entry2->path);
}
struct watchent *find_watchent_by_path(const char *path) {
	struct watchent tmp_watchent, *ret;

	tmp_watchent.path = path;
	ret = tfind(&tmp_watchent, &wd_info->path_tree_root, compare_entries_by_path);
	return ret;
}
int compare_wd_entries(const void *p1, const void *p2) {
	const struct watchent *entry1 = p1;
	const struct watchent *entry2 = p2;
	return entry1->wd - entry2->wd;
//	if (entry1->wd < entry2->wd)
//		return -1;
//	if (entry1->wd > entry2->wd)
//		return 1;
//	return 0;
}

struct watchent *find_watchent(int wd) {
	struct watchent *tester;
	struct watchent *ret;

	tester = new_watchent(wd, 0);
	ret = tfind(tester, &wd_info->tree_root, compare_wd_entries);
	kill_watchent(tester);
	return ret;
}
void walk_entry(const void *p, VISIT x,int level) {
	struct watchent *watchent = *(struct watchent **)p;

	if (x == leaf || x == postorder) {
		output("<%d>Walk on node %s %u %s  \n",
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

struct watchent *add_watch(char *path, enum watchent_type type, enum entry_added_cause added_cause) {
	int wd;
	struct watchent *new_ent;
	struct watchent *ret, **retptr;

	wd = inotify_add_watch(wd_info->inotify_fd, path, DIR_WATCH_EVENTS);
	new_ent = new_watchent(wd, path);
	retptr = tsearch(new_ent, &wd_info->tree_root, compare_wd_entries);

	if (retptr == NULL) {
		output("unable to add node\n");
		exit(1);
	}
	ret = *(struct watchent **)retptr;
	if (ret != new_ent) { /* already exists */
		kill_watchent(new_ent);
	} else {
		retptr = tsearch(new_ent, &wd_info->path_tree_root, compare_entries_by_path);
		if (ret != *(struct watchent **)retptr) {
			printf("Bummer...  watch entries don't match\n");
		}
		output("added %s watchent (%s): %d -> '%s': %p\n",
			watchent_type_string[type],
			entry_added_cause_string[added_cause],
			ret->wd, ret->path, ret);
		wd_info->active_wds++;
	}
	printf("added '%s' to tree...tree now:\n", path);
display_tree();
	return ret;
}

/* only manipulate the trees */
static void remove_wd_from_tree(struct watchent *ent) {
	printf("remove_wd_from_tree: %p - %d  %s\n", ent, ent->wd, ent->path);
	tdelete(ent, &wd_info->tree_root, compare_wd_entries);
//	if (!tmp)
//		wd_info->tree_root = NULL;
}
static void remove_path_from_tree(struct watchent *ent) {
//	struct watchent *tmp = tdelete(ent, &wd_info->path_tree_root, compare_entries_by_path);
	tdelete(ent, &wd_info->path_tree_root, compare_entries_by_path);
//	if (!tmp)
//		wd_info->path_tree_root = NULL;
}
/* watchent should already be known to be in the tree; watchent is not destroyed */
static void remove_watchent_from_trees(struct watchent *ent) {
	struct watchent *tester = new_watchent(ent->wd, ent->path);
//	struct watchent **ret = tfind
	struct watchent *real_ent;
	void *r1 = 0, *r2 = 0;

	real_ent = find_watchent(ent->wd);
	printf("real_ent = %p\n", real_ent);
	if (real_ent)
		real_ent = *(struct watchent **)real_ent;

	printf("real_ent = %p: %d %s\n", real_ent, real_ent->wd, real_ent->path);


	r1 = tfind(tester, &wd_info->tree_root, compare_wd_entries);
	if (r1) {
		printf("real_ent=%p, r1=%p, *r1=%p\n", real_ent, r1, *(struct watchent**)r1);
		real_ent = *(struct watchent **)r1;
		kill_watchent(tester);
		tester = new_watchent(real_ent->wd, real_ent->path);
		remove_wd_from_tree(tester);
		r2 = tfind(tester, &wd_info->path_tree_root, compare_entries_by_path);
		if (r2) {
			remove_path_from_tree(tester);
		}
		if (*(struct watchent **)r1 != *(struct watchent **)r2) {
			printf("bah...  pointers do not match: %p,%p / %p,%p\n", r1, *(struct watchent **)r1, r2, *(struct watchent **)r2);
		}
		kill_watchent(tester);
//		kill_watchent(real_ent);

//	remove_wd_from_tree(&ent);
//	remove_path_from_tree(&ent);
	wd_info->active_wds--;
	}
}
void ignore_watchent(int wd) {
	struct watchent *tmp_watchent;
	struct watchent *keep_ptr;

	printf("ignoring watchent wd=%d\n", wd);

output("tree pre-remove:\n");
display_tree();

	tmp_watchent = new_watchent(wd, 0);
	remove_watchent_from_trees(tmp_watchent);
output("tree post-remove");
display_tree();
	kill_watchent(tmp_watchent);

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
}

void process_file(char *path) {
	struct timespec tv;
	/* do nothing */

	tv.tv_sec=0; tv.tv_nsec=1000000;
	nanosleep(&tv, 0);
}

void add_watches_recursive(char *path, enum entry_added_cause added_cause) {
	/* add self directory */
	/* iterate children, recurse for each dir */
	int dir_fd;
	char buf[BUF_SIZE];
	char *bpos;
	int nread;
	struct linux_dirent64 *temp_de;
	struct stat st;
	struct watchent *new_watchent;

	if (stat(path, &st) == -1) {
		output("could not add watch for file/directory '%s', stat() failed with: %m\n", path);
//		int foo=1/0;
		return;
	}
	if (S_ISREG(st.st_mode)) {
#if WATCH_FILES
		add_watch(path, WATCHENT_TYPE_FILE, added_cause);
#endif
		process_file(path);
		return;
	}


//	new_watchent = add_watch(path, WATCHENT_TYPE_DIR, added_cause);
	add_watch(path, WATCHENT_TYPE_DIR, added_cause);

        if ((dir_fd = open(path, O_RDONLY | O_DIRECTORY)) == -1) {
		output("could not open directory '%s' to add watches recursively: %m\n",
			path);

		struct watchent *ent = find_watchent_by_path(path);
		if (ent) {

			ignore_watchent(ent->wd);
			kill_watchent(ent);
		}
//		int i = 1/0;
		return;
	}

	for (;;) {
		nread = syscall(SYS_getdents64, dir_fd, buf, BUF_SIZE);

		if (nread == -1)
			return;
		if (nread == 0)
			break;

		bpos = buf;
		while (bpos < buf + nread) {

			if (wd_info->interrupted)
				return;


			temp_de = (struct linux_dirent64 *)bpos;
			bpos += temp_de->d_reclen;
			if ((!strcmp(temp_de->d_name, ".")) || (!strcmp(temp_de->d_name, "..")))
				continue;

			switch (temp_de->d_type) {
				case DT_UNKNOWN:
					if (fstatat(dir_fd, temp_de->d_name, &st, AT_SYMLINK_NOFOLLOW) == -1) {
						output("could not add watch for file/directory '%s', fstatat() failed with: %m\n", path);
						break;
					}
					if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
						break;
				;;
				case DT_DIR:
				case DT_REG: {
					char *new_path;
					asprintf(&new_path, "%s/%s", path, temp_de->d_name);
					add_watches_recursive(new_path, ENTRY_ADDED_RECURSIVE);
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

void handle_events(void) {
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
	int i;

	for (;;) {
		len = read(wd_info->inotify_fd, buf, sizeof(buf));
		if (len == -1 && errno != EAGAIN)
			exit_fail("error reading from inotify_fd: %m\n");

		if (len <= 0)
			break;
		buf[len] = '\0'; /* may not be null-terminated */

//		for (ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
		for (ptr = buf ; ptr < buf + len ; ) {
			event = (const struct inotify_event *) ptr;

			if (event->wd < 0) {
				printf("AN ERROR OCCURRED... POSSIBLE OVERFLOW: %d\n", event->wd);
				output("AN ERROR OCCURRED... POSSIBLE OVERFLOW: %d\n", event->wd);
				goto next_event;
			}

			if (wd_info->interrupted)
				goto next_event;

			event_string = create_event_string(event);
			tree_watchent = find_watchent(event->wd);
			if (tree_watchent)
				tree_watchent = *(struct watchent **)tree_watchent;
			else {
				output("did not find a matching watchent for wd=%d event: %s (name='%s')\n", event->wd, event_string, event->name);
				twalk(wd_info->tree_root, dump_watch_tree);
				goto next_event_freestring;
			}
			wd_event_path = tree_watchent->path;
			if (event->len == 0)
				event_path = strdup(wd_event_path);
			else
				asprintf(&event_path, "%s/%s", wd_event_path, event->name);

			if (event_compare(event->mask, IN_DELETE|IN_ISDIR)) {
				printf("got an 'IN_DELETE|IN_ISDIR' for wd=%d, wd_event_path='%s', event->name='%s'\n", event->wd, wd_event_path, event->name);
			}

			handled_events = 0;

output("%s event: %s (path '%s')\n", (event->mask & IN_ISDIR) ? "DIRECTORY" : "FILE", event_string, event_path);

			if (event->mask & IN_ISDIR) {
				handled_events |= IN_ISDIR;

				if (event->mask & (IN_CREATE|IN_MOVED_TO)) {
					add_watches_recursive(event_path, ENTRY_ADDED_EVENT);
					handled_events |= (event->mask & (IN_CREATE|IN_MOVED_TO));
				}
				if (event->mask & IN_DELETE) { /* directory inside directory was removed; subdir should generate events--we can ignore */
					output("\t***** directory '%s' deleted ***** dir...IN_DELETE\n", event_path);
					printf("\t***** directory '%s' deleted ***** dir...IN_DELETE\n", event_path);
					handled_events |= IN_DELETE;
				}

				if (event->mask & IN_MOVED_FROM) /* wait for the IN_IGNORED event before killing the wd */
					handled_events |= IN_MOVED_FROM;
				if (event->mask & IN_DELETE_SELF) { /* wait for the IN_IGNORED event before killing the wd */
					output("\t***** directory '%s' deleted ***** dir...IN_DELETE_SELF\n", event_path);
					printf("\t***** directory '%s' deleted ***** dir...IN_DELETE_SELF\n", event_path);

					handled_events |= IN_DELETE_SELF;
				}

				if (event->mask & IN_IGNORED) {
					output("\t***** '%s' ignored ***** dir...IN_IGNORED\n", event_path);
					printf("\t***** '%s' ignored ***** dir...IN_IGNORED\n", event_path);
					ignore_watchent(event->wd);
					handled_events |= IN_IGNORED;
				}
				handled_events |= (DIR_SILENCE_EVENTS & event->mask);

			} else { /* event for a file, rather than a dir */
				if (event->mask & IN_DELETE_SELF) { /* stupid thing shows up as a file event */
				/* IN_DELETE_SELF -- supposed to only occur for a watched item, and since we're only watching dirs... */
					output("\t***** directory '%s' deleted *****\n", event_path);
					printf("\t***** directory '%s' deleted ***** file...IN_DELETE_SELF\n", event_path);
					printf("\t\tboo kazoo\n");
					handled_events |= IN_DELETE_SELF;
				}

				if (event->mask & IN_IGNORED) {
					output("\t***** directory '%s' ignored *****\n", event_path);
					printf("\t***** directory '%s' ignored *****\n", event_path);
					ignore_watchent(event->wd);
					handled_events |= IN_IGNORED;
				}

				if (event->mask & (IN_MOVED_TO|IN_ATTRIB|IN_CLOSE_WRITE)) {
					/* file moved in, touched, closed after possible write */
					process_file(event_path);
					handled_events |= (event->mask & (IN_MOVED_TO|IN_ATTRIB|IN_CLOSE_WRITE));
				}
				handled_events |= (FILE_DONTCARE_EVENTS & event->mask);
			}
//			output("\t'%s' for '%s': event->mask: 0x%08x, handled_events: 0x%08x\n",
//				event_string, event_path, event->mask, handled_events);
			if (event->mask != handled_events)
				output("\t*** WARNING *** unhandled events:\n"
					"\t'%s' for '%s': event->mask: 0x%08x, handled_events: 0x%08x\n",
					event_string, event_path, event->mask, handled_events);
next_event_freepath:
			free(event_path);
next_event_freestring:
			free(event_string);
next_event:
			ptr += sizeof(struct inotify_event) + event->len;
			if (wd_info->interrupted)
				break;
		}
	}
}

int listen_events(void) {
	struct pollfd fds[1];
	int poll_num;
	nfds_t nfds;

	/* Wait for events, empty watch tree, or interrupt */
	/* Prepare for polling inotify input */
	nfds = 1;
	fds[0].fd = wd_info->inotify_fd;
	fds[0].events = POLLIN;

	output("Listening for events.\n");
	while (wd_info->active_wds > 0 && !wd_info->interrupted) {
		poll_num = poll(fds, nfds, -1);
		if (poll_num == -1) {
			if (errno == EINTR)
				continue;
			exit_fail("poll error: %m");
		}

		if (poll_num > 0) {
			/* Inotify events are available */
			if (fds[0].revents & POLLIN)
				handle_events();
		}
	}
	return 0;
}
void exit_cleanup(void) {
	char *old_log;

	/* Close inotify file descriptor */
	close(wd_info->inotify_fd);
	tdestroy(wd_info->tree_root, kill_watchent);


	asprintf(&old_log, "%s/%s", wd_info->log_dir, wd_info->log_filename);
	close_log();
	free(wd_info->log_filename);

	printf("Please wait... compressing log\n");
	compress_log(old_log, 1);
	free(old_log);
	free(wd_info->stdout_device);

	free(wd_info);
}

int main(int argc, char *argv[]) {
	int i;
	char *path;


	if (argc < 2) {
		printf("Usage: %s PATH [PATH ...]\n", argv[0]);
		exit(EXIT_FAILURE);
	}


	if (do_init() != 0)
		return EXIT_FAILURE;

	for (i = 1 ; i < argc ; i++) {
		path = canonicalize_file_name(argv[i]);
		if (path) {
			add_watches_recursive(path, ENTRY_ADDED_CMDLINE);
			free(path);
		} else {
			output("Unable to watch path '%s' given on command line (%s): %m\n",
				path, argv[i]);
		}
	}
	if (wd_info->active_wds < 1) {
		output ("could not watch any paths\n");
		return EXIT_FAILURE;
	}
	output("Added %d watches at startup:\n", wd_info->active_wds);
	twalk(wd_info->tree_root, dump_watch_tree);
	output("path tree:\n");
	twalk(wd_info->path_tree_root, dump_watch_tree);

	listen_events();

	if (wd_info->interrupted) {
		output("exiting on interrupt.  current watch tree (%d watches):\n",
			wd_info->active_wds);
		twalk(wd_info->tree_root, dump_watch_tree);
		output("path tree:\n");
		twalk(wd_info->path_tree_root, dump_watch_tree);
	}
	if (wd_info->active_wds < 1) {
		output("exiting with no remaining watched paths\n");
	}

	exit_cleanup();

	return EXIT_SUCCESS;
}
