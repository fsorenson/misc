/*
	Frank Sorenson <sorenson@redhat.com>, 2022

	reproducer for Red Hat Bugzilla 2139504 - autofs segfault due to
	    lookup_mod->context address being freed and reused while
	    multiple threads were using it


	# gcc -Wall rhbz2139504_follow_paths.c -o rhbz2139504_follow_paths -g -O0 -lpcre

	autofs should be running, and should have a large amd file map


	
	# ./rhbz2139504_follow_paths -H /path_to_automount

	usage: ./rhbz2139504_follow_paths [-c <#_child_threads> | --children=<#_child_threads>] [ -H | --hups ] [ -p <autofs_path> | --path=<autofs_path> ] [<autofs_path>]


	specify the number of child threads if other than default (10):
		[-c <#_child_threads> | --children=<#_child_threads>]

	send the periodic SIGHUPs to automount:
		[ -H | --hups ]

	(there are multiple ways to specify the path--only the last specified will take effect)
		[ -p <autofs_path> | --path=<autofs_path> ]
	or just the final command-line argument
		[<autofs_path>]



	the program will determine the mapfile for the provided autofs_path by reading from /proc/self/mountinfo
	it will then fork child processes, each of which will then determine the longest paths in
		the map which begin with 'dir_a##' where ## represents the child process id (1 through the
		number specified)
	each child process will then sort the list of paths, then begin walking its way down each of the paths


	if specified, the parent process will send SIGHUP to 'automount' process periodically

	the parent process will also check whether 'automount' is dumping core (from /proc/<PID>/status) or
		the process has died; if either is the case, the parent process will send SIGINT to the
		child processes, which will then exit.


	the parent process will also output statistics about success/failure of the child processes
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <sched.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <utime.h>
#include <getopt.h>
#include <errno.h>
#include <pcre.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/syscall.h>

#define KiB (1024UL)

#define DEFAULT_CHILDREN 10
#define MAX_CHILDREN 100
#define BUF_SIZE (32*KiB)
#define RAND_STATE_SIZE 256
#define PATH_ARRAY_INCR 1024
#define OVECCOUNT 30 // multiple of 3

#define ANSI_CLREOL "\e[0K"

struct shared {
	bool do_hups;
	int num_children;

	char *autofs_path;
	char *mapfile;
	int child_pids;
	pid_t automount_pid;
	pid_t parent_pid;

	int automount_pid_status_fd;

	int dfd;

	struct random_data random_data;
	char random_statebuf[RAND_STATE_SIZE];

	uint64_t stat_count;
	uint64_t success_count;
	uint64_t failure_count;
	pid_t cpids[];
} shared_data;
struct shared *shared = NULL;

struct child_paths {
	int path_count;
	int paths_size;
	char **paths;
} paths_t;

void inc_stat_count(bool success) {
	__atomic_add_fetch(&shared->stat_count, 1, __ATOMIC_SEQ_CST);
	if (success)
		__atomic_add_fetch(&shared->success_count, 1, __ATOMIC_SEQ_CST);
	else
		__atomic_add_fetch(&shared->failure_count, 1, __ATOMIC_SEQ_CST);
}

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define min(a,b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a < _b ? _a : _b; \
})

#define free_mem(addr) do { if (addr) { free(addr); addr = NULL; } } while (0)
#define close_fd(fd) do { if (fd >= 0) { close(fd); fd = -1; } } while (0)

struct linux_dirent64 {
	ino64_t		d_ino;		/* 64-bit inode number */
	off64_t		d_off;		/* 64-bit offset to next structure */
	unsigned short	d_reclen;	/* Size of this dirent */
	unsigned char	d_type;		/* File type */
	char		d_name[];	/* Filename (null-terminated) */
};

uint32_t pickanum(int32_t _low, int32_t _high) { /* both inclusive */
	int32_t low, high;
	int32_t spread;
	int32_t r;

        if (_low < _high) { low = _low ; high = _high; }
        else { low = _high; high = _low; }

        spread = high - low;
        random_r(&shared->random_data, &r);
        return (r % (spread + 1)) + low;
}

int32_t *randomize_paths(int32_t *order, int count) {
	int32_t r;
	int i;

	for (i = 0 ; i < count ; i++)
		order[i] = i;
	while (count > 0) {
		int tmp_i;
		r = pickanum(0, count - 1);
		tmp_i = order[r];
		order[r] = order[count - 1];
		order[count - 1] = tmp_i;

		count--;
	}

	return order;
}

bool dir_exists(int dfd, const char *path) {
	struct stat st;

	if ((fstatat(dfd, path, &st, AT_NO_AUTOMOUNT)) < 0) {
		if (errno == ENOENT)
			return false;
		return false; // guess this is still false... at least, we can't get at it, for some reason
	}
	if ((st.st_mode & S_IFMT) == S_IFDIR)
		return true;
	return false;
}

int increase_paths(struct child_paths *child_paths) {
	char **new_path_array;

	if ((new_path_array = reallocarray(child_paths->paths, sizeof(child_paths->paths[0]), child_paths->paths_size + PATH_ARRAY_INCR)) == NULL) {
		output("unable to allocate memory for the paths: %m\n");
		exit(1);
	}
	child_paths->paths = new_path_array;
	child_paths->paths_size += PATH_ARRAY_INCR;

	return 0;
}
struct child_paths *alloc_paths(void) {
	struct child_paths *child_paths = malloc(sizeof(child_paths->paths[0]));
	memset(child_paths, 0, sizeof(*child_paths));
	return child_paths;
}
int add_path(struct child_paths *child_paths, char *new_path) {
	if (child_paths->path_count == child_paths->paths_size)
		increase_paths(child_paths);

	child_paths->paths[child_paths->path_count++] = new_path;

	return child_paths->path_count;
}

bool pid_still_running(pid_t pid) {
	if ((kill(pid, 0)) == 0)
		return true;
	return false;
}

pid_t get_automount_pid(void) {
	struct linux_dirent64 *de;
	pid_t automount_pid = -1;
	char *buf = NULL, *bpos;
	char link_buf[4096];
	int proc_dfd = -1;
	char exe_buf[32];
	int nread;

	buf = malloc(BUF_SIZE);

	if ((proc_dfd = open("/proc/", O_RDONLY|O_DIRECTORY)) < 0) {
		output("error opening /proc: %m\n");
		exit(1);
	}
	while (42) {
		if ((nread = syscall(SYS_getdents64, proc_dfd, buf, BUF_SIZE)) < 0)
			goto out;
		if (nread == 0)
			break;

		bpos = buf;
		while (bpos < buf + nread) {
			char *ptr;
			pid_t pid;

			de = (struct linux_dirent64 *)bpos;
			bpos += de->d_reclen;

			if ((pid = strtol(de->d_name, &ptr, 10)) <= 0 || pid == LONG_MAX || *ptr != '\0') { // not a pid
			} else {
				int len;

				snprintf(exe_buf, sizeof(exe_buf) - 1, "%d/exe", pid);
				if ((len = readlinkat(proc_dfd, exe_buf, link_buf, sizeof(link_buf) - 1)) < 0) { // maybe a kernel thread?
					continue;
				}
				link_buf[len < sizeof(link_buf) ? len : sizeof(link_buf) - 1] = '\0';
				char *exename = basename(link_buf);

				if (!strcmp(exename, "automount")) {
					automount_pid = pid;
					goto out;
				}
			}
		}
	}

out:
	if (buf)
		free(buf);
	if (proc_dfd >= 0)
		close(proc_dfd);

	return automount_pid > 0 ? automount_pid : 0;
}
int open_pid_status(pid_t pid) {
	char *path = NULL;
	int fd;

	asprintf(&path, "/proc/%d/status", pid);

	fd = open(path, O_RDONLY);
	free_mem(path);

	return fd;
}
bool check_automount_dumping(void) {
	int ovector[OVECCOUNT], nread, ret = false, rc;
	static pcre *re = NULL;
	const char *error;
	int erroffset;
	char buf[4096];

//	CoreDumping:	0
	if (re == NULL) {
		if ((re = pcre_compile("^CoreDumping:\\s+([01])$", PCRE_MULTILINE,
			&error, &erroffset, NULL)) == NULL) {
			output("error compiling regex: '%s' at character %d\n", error, erroffset);
			exit(1);
		}
	}
	memset(buf, 0, sizeof(buf));

	if ((nread = pread(shared->automount_pid_status_fd, buf, sizeof(buf), 0)) < 0) {
		if (errno == ESRCH)
			return false;
		output("error reading from /proc/<pid>/status for automount: %m\n");
//		return true;
		return false;
	}

	if ((rc = pcre_exec(re, NULL, buf, nread, 0, 0, ovector, sizeof(ovector)/sizeof(ovector[0]))) < 0) {
		switch (rc) {
			case PCRE_ERROR_NOMATCH:
				break;
			default:
				output("matching error %d\n", rc);
				break;
		}
	}

	if (buf[ovector[2]] == '1')
		ret = true;
	else if (buf[ovector[2]] != '0') {
		output("error...  for CoreDumping, expected '0' or '1', but found '%c'\n", buf[ovector[2]]);
		ret = false;
	}

	return ret;
}

int extract_line(char *buf, int buf_bytes, char **line) {
	char *ptr = memchr(buf, '\n', buf_bytes);

	if (ptr == NULL)
		return 0;

	int len = ptr - buf;
	*line = strndup(buf, len);

	return len + 1;
}
int extract_line2(char *buf, int buf_bytes, char **line, bool eof) {
	char *ptr = memchr(buf, '\n', buf_bytes);
	int len;

	if (ptr)
		len = ptr - buf;
	else if (!eof)
		return 0;
	else // no newline and eof
		len = buf_bytes;

	*line = strndup(buf, len);

	return len + 1;
}

typedef int (*match_action_t)(void *data, const char *buf, int *ovector);

int match_mountinfo_autofs_path(void *ptr, const char *line, int *ovector) {
	char **filename = ptr;

	*filename = strndup(line + ovector[2], ovector[3] - ovector[2]);

	return 1;
}
int add_mapfile_path(void *ptr, const char *line, int *ovector) {
	struct child_paths *child_paths = ptr;
	char *new_path = strndup(line + ovector[2], ovector[3] - ovector[2]);
	add_path(child_paths, new_path);
	return 1;
}

int regex_test_and_act(match_action_t action, void *ptr, pcre *re, const char *line) {
	int line_len = strlen(line), ret = 0;
	int ovector[OVECCOUNT], rc;

	if ((rc = pcre_exec(re, NULL, /* no extra data */
		line, line_len, 0, /* start at offset 0 */
		0,		/* default options */
		ovector, sizeof(ovector)/sizeof(ovector[0]))) < 0) {

		switch (rc) {
			case PCRE_ERROR_NOMATCH:
				break;
			default:
				output("matching error %d\n", rc);
				break;
		}
		goto out;
	}

	ret = 1;
	action(ptr, line, ovector); /* we have a match, so do the thing */

out:
	return ret;
}

int parse_file_generic(void *ptr, const char *filename, const char *regex_str, match_action_t action) {
	int buf_bytes = 0, erroffset, fd = -1;
	const char *error;
	char *buf = NULL;
	bool eof = false;
	pcre *re = NULL;

	if ((re = pcre_compile(
		regex_str,	/* the pattern */
		0,		/* default options */
		&error,
		&erroffset,
		NULL)		/* use default character tables */
		) == NULL) {

		output("PCRE compilation failed at offset %d: %s\n", erroffset, error);
		exit(1);
	}
	buf = malloc(BUF_SIZE);

	if ((fd = open(filename, O_RDONLY)) < 0) {
		output("error opening mapfile '%s': %m\n", shared->mapfile);
		exit(1);
	}
	while (!eof) {
		int nread;
		if ((nread = read(fd, buf + buf_bytes, BUF_SIZE - buf_bytes)) == 0)
			eof = true;
		else if (nread < 0) {
			output("error reading from mapfile: %m\n");
			exit(1);
		}
		buf_bytes += nread;

		if (buf_bytes) {
			char *line;
			int line_len;

//			while ((line_len = extract_line(buf, buf_bytes, &line)) > 0) {
			while ((line_len = extract_line2(buf, buf_bytes, &line, eof)) > 0) {
				regex_test_and_act(action, ptr, re, line);

				memmove(buf, buf + line_len, buf_bytes - line_len);
				buf_bytes -= line_len;
				free(line);
			}
/*
			if (eof && buf_bytes) {
				line = strndup(buf, buf_bytes);
				regex_test_and_act(action, ptr, re, line);
				free(line);
				buf_bytes = 0;
			}
*/
		}
	}

	if (fd >= 0)
		close(fd);
	if (buf)
		free(buf);

	if (re)
		pcre_free(re);

	return 0;
}

int mountinfo_get_map_path(void) {
	char *regex_str = NULL;
	asprintf(&regex_str, "^[0-9]+\\s+[0-9]+\\s+[0-9:]+\\s+/\\s+%s\\s+[^\\s]+\\s+[^\\s]+\\s-\\s+autofs\\s+(/[^\\s]+)\\s+", shared->autofs_path);

	parse_file_generic(&shared->mapfile, "/proc/self/mountinfo", regex_str, &match_mountinfo_autofs_path);

	if (regex_str)
		free(regex_str);
	return 0;
}

static char *depth_regexes[] = {
	[0] = "^(dir_a%d) [^ ]+",
	[1] = "^(dir_a%d/dir_a%1$db[0-9]+) [^ ]+",
	[2] = "^(dir_a%d/dir_a%1$db[0-9]+/dir_a%1$db[0-9]+c[0-9]+) [^ ]+",
	[3] = "^(dir_a%d/dir_a%1$db[0-9]+/dir_a%1$db[0-9]+c[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+) [^ ]+",
	[4] = "^(dir_a%d/dir_a%1$db[0-9]+/dir_a%1$db[0-9]+c[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+) [^ ]+",
	[5] = "^(dir_a%d/dir_a%1$db[0-9]+/dir_a%1$db[0-9]+c[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+) [^ ]+",
	[6] = "^(dir_a%d/dir_a%1$db[0-9]+/dir_a%1$db[0-9]+c[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+) [^ ]+",
	[7] = "^(dir_a%d/dir_a%1$db[0-9]+/dir_a%1$db[0-9]+c[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+) [^ ]+",
	[8] = "^(dir_a%d/dir_a%1$db[0-9]+/dir_a%1$db[0-9]+c[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+i[0-9]+) [^ ]+",
	[9] = "^(dir_a%d/dir_a%1$db[0-9]+/dir_a%1$db[0-9]+c[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+i[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+i[0-9]+j[0-9]+) [^ ]+",
	[10] = "^(dir_a%d/dir_a%1$db[0-9]+/dir_a%1$db[0-9]+c[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+i[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+i[0-9]+j[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+i[0-9]+j[0-9]+k[0-9]+) [^ ]+",
	[11] = "^(dir_a%d/dir_a%1$db[0-9]+/dir_a%1$db[0-9]+c[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+i[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+i[0-9]+j[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+i[0-9]+j[0-9]+k[0-9]+/dir_a%1$db[0-9]+c[0-9]+d[0-9]+e[0-9]+f[0-9]+g[0-9]+h[0-9]+i[0-9]+j[0-9]+k[0-9]+l[0-9]+) [^ ]+",

//	[4] = "^(dir_a%d/dir_a%1$db[0-9]+/dir_a%1$db[0-9]+c[0-9]+) [^ ]+",
//	[5] = "^(dir_a%d/dir_a%1$db[0-9]+/dir_a%1$db[0-9]+c[0-9]+) [^ ]+",
};
int get_paths_at_depth(struct child_paths *child_paths, int child_id, int depth) {
	char *regex_str = NULL;

	if (depth < (sizeof(depth_regexes)/sizeof(depth_regexes[0])))
		asprintf(&regex_str, depth_regexes[depth], child_id);
	else
		return 0;

	parse_file_generic(child_paths, shared->mapfile, regex_str, &add_mapfile_path);

	if (regex_str)
		free(regex_str);
	return child_paths->path_count;
}

int get_mapfile_paths(struct child_paths *child_paths, int child_id) {
	int ret, depth;

	for (depth = sizeof(depth_regexes)/sizeof(depth_regexes[0]) - 1 ; depth >= 0 ; depth--) {
		if ((ret = get_paths_at_depth(child_paths, child_id, depth)) > 0) {
			output("got %d paths with depth %d\n", ret, depth);
			return ret;
		}
	}
	return 0;
}

char *cleanup_path(const char *orig_path) {
	char *new_path = strdup(orig_path);
	const char *p1 = orig_path;
	char *p2 = new_path, lastchar = '\0';

	while (*p1 != '\0') {
		if ((*p1 == '/' && lastchar != '/') || (*p1 != '/'))
			lastchar = *p2++ = *p1++;
		else
			p1++;
	}
	*p2 = '\0';
	int len = strlen(new_path);
	while (len > 1 && new_path[len - 1] == '/')
		new_path[(len--) - 1] = '\0';

	char *tmp_path = strdup(new_path);
	free_mem(new_path);

	return tmp_path;
}
void cleanup_free_path(char **p) {
	char *new_path = cleanup_path(*p);
	free_mem(*p);
	*p = new_path;
}
	

int follow_path_iterative(int dfd, const char *path) {
	char *path_copy = strdup(path), *p = path_copy, *this_component = NULL, *next_p;
	int ret = EXIT_SUCCESS, next_dfd = -1, len;
	struct stat st;

	if (!path || *path == '\0')
		goto out;

	if (*path == '/')
		dfd = openat(AT_FDCWD, "/", O_RDONLY|O_DIRECTORY);
	else
		dfd = dup(dfd); // make a copy

	while (*p == '/' && *p != '\0')
		p++;
	len = strlen(p);
	while (len > 0 && p[len - 1] == '/') {
		p[len - 1] = '\0';
		len--;
	}

	while (p && *p != '\0') {
		while (*p == '/' && *p != '\0')
			p++;

		if (*p == '\0')
			break;

		next_p = strstr(p, "/");
		if (next_p) {
			*next_p = '\0';
			next_p++;
		}

		this_component = strdup(p);
		p = next_p;

		if (!p || *p == '\0') {
			if (fstatat(dfd, this_component, &st, AT_SYMLINK_NOFOLLOW))
				ret = EXIT_FAILURE;
			close_fd(dfd);
			goto out;
		}
		next_dfd = openat(dfd, this_component, O_RDONLY|O_DIRECTORY);

		close_fd(dfd);
		free_mem(this_component);
		dfd = next_dfd;
		next_dfd = -1;

		if (dfd < 0) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}

out:
	free_mem(this_component);
	free_mem(path_copy);

	return ret;
}


int one_stat_child(int child_id) {
	struct child_paths *child_paths;
	int *order;
	int i;

	child_paths = alloc_paths();

	get_mapfile_paths(child_paths, child_id);

	if (! child_paths->path_count) {
		output("child %d (%d) unable to locate any paths; exiting\n", child_id, getpid());
		return 0;
	}
	order = malloc(sizeof(int) * child_paths->path_count);

	output("child %d (%d) calling stat() on %d paths\n", child_id, getpid(), child_paths->path_count);
	while (42) {
		randomize_paths(order, child_paths->path_count);

		for (i = 0 ; i < child_paths->path_count ; i++) {
			int ret;
			ret = follow_path_iterative(shared->dfd, child_paths->paths[order[i]]);

			inc_stat_count(ret == 0);

			usleep(pickanum(25, 99) * 10000); // sleep this number of centisecs
		}
	}
	return 0;
}
void handle_child_exit(int sig, siginfo_t *info, void *ucontext) {
	int status, i;
	pid_t pid;

	while ((pid = wait4(-1, &status, WNOHANG, NULL)) != -1) {
		bool found = false;
		if (pid == 0)
			return;

		for (i = 0 ; i < shared->num_children ; i++) {
			if (shared->cpids[i] == pid) {
				found = true;
				if (WIFSIGNALED(status)) {
					output("child %d (pid %d) exited with signal %d%s\n", i + 1, pid,
						WTERMSIG(info->si_signo), WCOREDUMP(status) ? " and dumped core" : "");
					shared->cpids[i] = 0;
					shared->child_pids--;
				} else if (WIFEXITED(status)) {
//					output("child %d (pid %d) exited with %d\n", i + 1, pid, WEXITSTATUS(status));
//					shared->cpids[i] = 0;
					shared->child_pids--;
				} else if (WIFSTOPPED(status))
					output("child %d (pid %d) stopped by signal %d\n", i + 1, pid, WSTOPSIG(status));
				else if (WIFCONTINUED(status))
					output("child %d (pid %d) continued\n", i + 1, pid);
				else
					output("child %d (pid %d) had something happen... no idea what\n", i + 1, pid);
			}
		}
		if (! found)
			output("unable to find exiting child pid %d (cue Billy Jean)\n", pid);
	} /* wait on more children? */
}
void kill_children(int sig) {
	int i;

	for (i = 0 ; i < shared->num_children ; i++)
		if (shared->cpids[i])
			kill(shared->cpids[i], sig); /* pass it on */
}
void handle_sig(int sig) {
	kill_children(sig);
}

void output_stat_counts(bool newline) {
	static uint64_t last_stat_count = 0, last_success_count = 0, last_failed_count = 0;
	uint64_t stat_count, success_count, failed_count;
	bool values_changed = false;

	stat_count = __atomic_load_n(&shared->stat_count, __ATOMIC_SEQ_CST);
	success_count = __atomic_load_n(&shared->success_count, __ATOMIC_SEQ_CST);
	failed_count = __atomic_load_n(&shared->failure_count, __ATOMIC_SEQ_CST);

	if (stat_count != last_stat_count || success_count != last_success_count || failed_count != last_failed_count)
		values_changed = true;


	if (newline)
		output(ANSI_CLREOL "stats: %" PRIu64 "; success: %" PRIu64 "; failure: %" PRIu64 "\n",
			stat_count, success_count, failed_count);
	else if (values_changed)
		output(ANSI_CLREOL "stats: %" PRIu64 "; success: %" PRIu64 "; failure: %" PRIu64 "\r",
			stat_count, success_count, failed_count);
}

#define MIN_STAT_THRESHOLD (1) /* at least this many completions before we fire off another SIGHUP */
void do_parent_work(void) {
	uint64_t threshold_stat_count = MIN_STAT_THRESHOLD;
	uint32_t hup_count = 0;
	while (42) {
		if (check_automount_dumping() || ! pid_still_running(shared->automount_pid))
			goto automount_dead;

		output_stat_counts(false);

		if (shared->do_hups && __atomic_load_n(&shared->stat_count, __ATOMIC_SEQ_CST) >= threshold_stat_count) {
			int fd;
			output("\nsending SIGHUP %u\n", ++hup_count);

			fd = open(shared->mapfile, O_RDWR);
			posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
			close(fd);

			kill(shared->automount_pid, SIGHUP);
			threshold_stat_count = __atomic_load_n(&shared->stat_count, __ATOMIC_SEQ_CST) + MIN_STAT_THRESHOLD;
		}
		usleep(100000);
		if (shared->child_pids == 0)
			break;
	}

automount_dead:
	if (check_automount_dumping())
		output("automount dumping core\n");

	if (! pid_still_running(shared->automount_pid))
		output("automount dead...  success\n");

	if (shared->child_pids)
		kill_children(SIGINT);

	while (shared->child_pids > 0)
		usleep(100000);
}

int usage(const char *exe) {
	output("usage: %s [-c <#_child_threads> | --children=<#_child_threads>] [ -H | --hups ] [ -p <autofs_path> | --path=<autofs_path> ] [<autofs_path>]\n", exe);
	return EXIT_FAILURE;
}

int parse_args(int argc, char *argv[]) {
	int num_children = DEFAULT_CHILDREN;
	int opt = 0, long_index = 0;
	static struct option long_options[] = {
		{ "children",	required_argument,	0, 'c' },
		{ "path",	required_argument,	0, 'p' },
		{ "hups",	no_argument,		0, 'H' },
		{ NULL, 0, 0,  0 },
	};
	char *autofs_path = NULL;
	int ret = EXIT_SUCCESS;
	bool do_hups = false;

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "c:Hp:", long_options, &long_index)) != -1) {
		switch (opt) {
			case 'c':
				num_children = strtol(optarg, NULL, 10);
				break;
			case 'H':
				do_hups = true;
				break;
			case 'p':
				free_mem(autofs_path);
				if (!strncmp("/", optarg, 1)) {
					output("autofs_path '%s' should be an absolute path\n", optarg);
					ret = EXIT_FAILURE;
					goto out;
				}
				autofs_path = strdup(optarg);
				break;
			default:
				ret = EXIT_FAILURE;
				goto out;
				break;
		}
	}

	if (optind < argc && !autofs_path) {
		free_mem(autofs_path);
		autofs_path = strdup(argv[optind++]);
	}
	if (!autofs_path) {
		output("no path specified\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	if (optind < argc) {
		int i;

		output("extra args: ");
		for (i = optind ; i < argc ; i++)
			output(" '%s'", argv[i]);
		output("\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	num_children = min(num_children, MAX_CHILDREN);
	if (num_children <= 0)
		num_children = DEFAULT_CHILDREN;

out:
	if (ret == EXIT_SUCCESS) {
		cleanup_free_path(&autofs_path);

		if (strncmp("/", autofs_path, 1)) {
			output("autofs_path '%s' should be an absolute path\n", autofs_path);
			ret = EXIT_FAILURE;
			goto out2;
		}
		if (!dir_exists(AT_FDCWD, autofs_path)) {
			output("can't access autofs path '%s': %m\n", autofs_path);
			ret = EXIT_FAILURE;
			goto out2;
		}

		shared = mmap(NULL, sizeof(*shared) + sizeof(shared->cpids[0]) * num_children, PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		shared->num_children = num_children;
		shared->autofs_path = autofs_path;
		shared->do_hups = do_hups;
	}
out2:
	if (ret != EXIT_SUCCESS) {
		usage(argv[0]);
		free_mem(autofs_path);
	}

	return ret;
}
void block_unblock_SIGCHLD(void *func) {
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	if (func) { // unblock
		sigfillset(&sa.sa_mask);
		sa.sa_handler = NULL;
		sa.sa_sigaction = func;
		sigaction(SIGCHLD, &sa, NULL);


		sigemptyset(&sa.sa_mask);
		sigaddset(&sa.sa_mask, SIGCHLD);
		sigprocmask(SIG_UNBLOCK, &sa.sa_mask, NULL);
	} else { // block
		sigemptyset(&sa.sa_mask);
		sigaddset(&sa.sa_mask, SIGCHLD);
		sigprocmask(SIG_BLOCK, &sa.sa_mask, NULL);
	}
}

int main(int argc, char *argv[]) {
	struct sigaction sa;
	pid_t cpid;
	int i;

	if ((parse_args(argc, argv)) != EXIT_SUCCESS)
		return EXIT_FAILURE;

	mountinfo_get_map_path();
	if (! shared->mapfile) {
		output("unable to find mapfile for '%s'\n", shared->autofs_path);
		return EXIT_FAILURE;
	}
	output("mapfile for mountpoint %s is %s\n", shared->autofs_path, shared->mapfile);

	initstate_r(time(NULL) % INT_MAX, shared->random_statebuf, RAND_STATE_SIZE, &shared->random_data);

	shared->parent_pid = getpid();

	shared->automount_pid = get_automount_pid();


	if (shared->automount_pid <= 0) {
		output("automount not running\n");
		return EXIT_FAILURE;
	}

	shared->automount_pid_status_fd = open_pid_status(shared->automount_pid);

	if ((shared->dfd = open(shared->autofs_path, O_RDONLY|O_DIRECTORY)) < 0) {
		output("error opening base path '%s': %m\n", shared->autofs_path);
		return EXIT_FAILURE;
	}

	block_unblock_SIGCHLD(NULL); // no function pointer == block

	for (i = 0 ; i < shared->num_children ; i++) {
		if ((cpid = fork()) == 0)
			return one_stat_child(i + 1);
		else if (cpid > 0) {
			shared->cpids[i] = cpid;
			shared->child_pids++;
		} else {
			output("failed to fork: %m\n");
			return EXIT_FAILURE;
		}
	}

	memset(&sa, 0, sizeof(sa));
	sigfillset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &handle_sig;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	block_unblock_SIGCHLD(&handle_child_exit);

	do_parent_work();

	output_stat_counts(true);

	return EXIT_FAILURE;
}
