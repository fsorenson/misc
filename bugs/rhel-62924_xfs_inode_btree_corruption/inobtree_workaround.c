/*
	Frank Sorenson <sorenson@redhat.com>, 2024

	Interpose glibc functions which create filesystem objects (files, directories,
	  special files, etc.) in order to work around Red Hat issue RHEL-62924:
	  https://issues.redhat.com/browse/RHEL-62924

	The bug results in EUCLEAN returned from syscalls (and therefore library functions)
	  when the object being created is allocated from the very end of the final AG of
	  an xfs filesystem, such that the the allocation would go beyond the end of the
	  filesystem.

	note:
	  the kernel attempts to allocate files in a directory out of the same AG as the
	    directory itself, so if the directory's inode is in the final AG, the bug
	    will occur persistently in that directory
	  the kernel rotates through AGs when creating subdirectoriries, so directory
	    creation will only fail with EUCLEAN once every agcount attempts

	therefore:
	  directory creation failure can be retried, and should be allocated out of
	    a different AG (and should therefore succeed, unless all other AGs are full,
	    or a different error occurs)
	  when file creation failure occurs, creating the file in a different directory
	    (whose inode is in a different AG) should succeed, and the file can then be
	    moved to the desired directory

	this program interposes glibc functions in the following way:
	  - if directory creation fails, retry the operation
	  - if file creation fails, create a subdirectory, create the file in the
	    new subdirectory, move the file to the desired directory, and remove the
	    temporary directory

	interposed functions include the following:
	  creat, open, openat
	  mkdir, mkdirat
	  fopen
	  symlink, symlinkat
	  mknod, mknodat
	  mkfifo, mkfifoat

	some functions are intentionally not implemented (such as bind used to create
	  a named socket) to discourage long-term use of this loadable library; this
	  library is intended for use only long enough to install a new kernel in
	  order to resolve the bug

	compile:
	  # gcc -Wall inobtree_workaround.c -o inobtree_workaround.so -shared -fPIC -ldl

	usage (bash):
	  # export LD_PRELOAD=$(pwd)/inobtree_workaround.so
	  # rpm -ivh kernel-...
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/time.h>

#define DEBUG 0

#define free_mem(p) do { \
	if (p) { \
		free(p); \
		p = NULL; \
	} \
} while (0)

typedef int (*creat_t)(const char *pathname, mode_t mode);
typedef int (*open_t)(const char *pathname, int flags, ...);
typedef int (*openat_t)(int dirfd, const char *pathname, int flags, ...);
typedef int (*mkdir_t)(const char *pathname, mode_t mode);
typedef int (*mkdirat_t)(int dirfd, const char *pathname, mode_t mode);
typedef FILE *(*fopen_t)(const char *pathname, const char *mode);

// hardlinks don't allocate new inodes, so these probably don't need to be implemented
//typedef int (*link_t)(const char *path1, const char *path2);
//typedef int (*linkat_t)(int fd1, const char *path1, int fd2, const char *path2, int flag);
typedef int (*symlink_t)(const char *path1, const char *path2);
typedef int (*symlinkat_t)(const char *path1, int fd, const char *path2);
typedef int (*mknod_t)(const char *path, mode_t mode, dev_t dev);
typedef int (*mknodat_t)(int fd, const char *path, mode_t mode, dev_t dev);
typedef int (*mkfifo_t)(const char *pathname, mode_t mode);
typedef int (*mkfifoat_t)(int dfd, const char *pathname, mode_t mode);

creat_t real_creat = NULL;
open_t real_open = NULL;
openat_t real_openat = NULL;
mkdir_t real_mkdir = NULL;
mkdirat_t real_mkdirat = NULL;
fopen_t real_fopen = NULL;
//link_t real_link = NULL;
//linkat_t real_linkat = NULL;
symlink_t real_symlink = NULL;
symlinkat_t real_symlinkat = NULL;
mknod_t real_mknod = NULL;
mknodat_t real_mknodat = NULL;
mkfifo_t real_mkfifo = NULL;
mkfifoat_t real_mkfifoat = NULL;

#define output(args...) do { \
	fprintf(stderr, args); \
} while (0)

#if DEBUG
#define debug_workaround_success(_type, _dfd, _path, _func) do { \
	char dfd_str[10] = "AT_FDCWD"; \
	if (_dfd != AT_FDCWD) \
		snprintf(dfd_str, sizeof(dfd_str) - 1, "%d", _dfd); \
	output("worked around %s creation for %s:%s on %s call\n", \
		_type, dfd_str, _path, _func); \
} while (0)
#else
#define debug_workaround_success(args) do { } while (0)
#endif

const char valid_chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
#define TEMP_NAME_LEN 64
char *make_tempname(void) {
	static bool randomized = false;
	char *temp = malloc(TEMP_NAME_LEN + 1);
	int i;

	if (!randomized) {
		struct timeval tv;
		gettimeofday(&tv, 0);
		srandom((long)tv.tv_usec);
		randomized = true;
	}

	for (i = 0 ; i < TEMP_NAME_LEN ; i++)
		temp[i] = valid_chars[random() % (sizeof(valid_chars) - 1)];
	temp[TEMP_NAME_LEN] = '\0';

	return temp;
}

#define open_get_mode_param() ({ \
	mode_t mode; \
	va_list arg_ptr; \
	va_start(arg_ptr, flags); \
	mode = va_arg(arg_ptr, int); \
	va_end(arg_ptr); \
	mode; \
})

#define get_real(_func) if (! real_##_func) { \
	char *error; \
	dlerror(); \
	real_##_func = dlsym(RTLD_NEXT, #_func); \
	if ((error = dlerror()) != NULL) { \
		output("%s getting address for %s\n", error, #_func); \
		exit(EXIT_FAILURE); \
	} \
}
#define call_real(_func, args...) ({ \
	get_real(_func); \
	real_##_func(args); \
})

int mkdirat_workaround(int dfd, const char *path, int mode) {
	int ret, try;

	for (try = 0 ; try < 2 ; try++) {
		if (((ret = call_real(mkdirat, dfd, path, mode)) == 0) ||
			(errno != EUCLEAN))
#if DEBUG
			{
				if (ret == 0 && try > 0) {
					char dfd_str[10] = "AT_FDCWD";
					if (dfd != AT_FDCWD)
						snprintf(dfd_str, sizeof(dfd_str) - 1, "%d", dfd);
					output("worked around directory creation for %s:'%s' on mkdir call %d\n",
						dfd_str, path, try + 1);
				}
				return ret;
			}
#else
			return ret;
#endif


	}

	return ret;
}
// dirname and basename can modify the path, and return a static string... fix both
char *dirname2(const char *path) {
	char *temp = NULL, *temp2 = NULL;

	temp = strdup(path);
	temp2 = strdup(dirname(temp));
	free_mem(temp);
	return temp2;
}
char *basename2(const char *path) {
	char *temp = NULL, *temp2 = NULL;

	temp = strdup(path);
	temp2 = strdup(basename(temp));
	free_mem(temp);

	return temp2;
}

int create_file_workaround(int dfd, const char *path, int flags, mode_t mode) {
	char *target_dir = NULL, *temp_target_dir = NULL, *temp_dirname = NULL;
	char *target_filename = NULL, *temp_target_filename = NULL;
	struct stat st;
	int ret = -1;

	get_real(openat);

	target_dir = dirname2(path);
	target_filename = basename2(path);

new_name:
	temp_dirname = make_tempname();

	asprintf(&temp_target_dir, "%s/%s", target_dir, temp_dirname);
	// check for the (unlikely) possibility we've got a dir entry by that obscure name
	if ((ret = fstatat(dfd, temp_target_dir, &st, AT_SYMLINK_NOFOLLOW)) == 0) {
		free_mem(temp_dirname);
		free_mem(temp_target_dir);
		goto new_name;
	}
	// make sure we failed because it didn't exist, not for some other reason
	if (errno != ENOENT)
		goto out;

	if ((ret = mkdirat_workaround(dfd, temp_target_dir, 0755)) < 0)
		goto out;

	asprintf(&temp_target_filename, "%s/%s", temp_target_dir, target_filename);

	if ((ret = call_real(openat, dfd, temp_target_filename, flags, mode)) >= 0) {
		if ((renameat(dfd, temp_target_filename, dfd, path))) {
//			output("error renaming '%s' to '%s': %m\n",
//				tempfilename, path);
			close(ret);
			unlinkat(dfd, temp_target_filename, 0);
			unlinkat(dfd, temp_target_dir, AT_REMOVEDIR);
			ret = -1;
			goto out;
		}
		unlinkat(dfd, temp_target_dir, AT_REMOVEDIR);
		errno = 0;

#if DEBUG
		char dfd_str[10] = "AT_FDCWD";
		if (dfd != AT_FDCWD)
			snprintf(dfd_str, sizeof(dfd_str) - 1, "%d", dfd);
		output("worked around file creation for %s:'%s'\n",
			dfd_str, path);
#endif
		goto out;
	} else {
		ret = -1;
		errno = EUCLEAN;
	}

out:
	free_mem(target_dir);
	free_mem(temp_target_dir);
	free_mem(target_filename);
	free_mem(temp_target_filename);
	free_mem(temp_dirname);

	return ret;
}


int creat(const char *path, mode_t mode) {
	int ret;

	// successful open, or a different error occurred
	if (((ret = call_real(creat, path, mode)) >= 0) || errno != EUCLEAN)
		return ret;

	return create_file_workaround(AT_FDCWD, path, O_CREAT|O_WRONLY|O_TRUNC, mode);
}
int open(const char *path, int flags, ...) {
	mode_t mode;
	int ret;

	if (!(flags & O_CREAT))
		return call_real(openat, AT_FDCWD, path, flags);

	mode = open_get_mode_param();

	if (((ret = call_real(openat, AT_FDCWD, path, flags, mode)) >= 0) || errno != EUCLEAN)
		return ret;

	return create_file_workaround(AT_FDCWD, path, flags, mode);
}
//int openat(int dirfd, const char *path, int flags);
//int openat(int dirfd, const char *path, int flags, mode_t mode);
int openat(int dfd, const char *path, int flags, ...) {
	mode_t mode;
	int ret;

	if (!(flags & O_CREAT))
		return call_real(openat, dfd, path, flags);

	mode = open_get_mode_param();

	if (((ret = call_real(openat, dfd, path, flags, mode)) >= 0) || errno != EUCLEAN)
		return ret;

	return create_file_workaround(dfd, path, flags, mode);
}

// conversion just so we can reuse the create_file_workaround()...  laziness++
// conversions derived from testing
int fopen_mode_to_flags(const char *mode) {
// openat(AT_FDCWD, "testfile_fopen_r", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000041>
// openat(AT_FDCWD, "testfile_fopen_rb", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000036>
// openat(AT_FDCWD, "testfile_fopen_rt", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000038>
	if (!strcmp(mode, "r") || !strcmp(mode, "rb") || !strcmp(mode, "rt"))
		return O_RDONLY;

// openat(AT_FDCWD, "testfile_fopen_r+", O_RDWR) = -1 ENOENT (No such file or directory) <0.000039>
// openat(AT_FDCWD, "testfile_fopen_rb+", O_RDWR) = -1 ENOENT (No such file or directory) <0.000037>
// openat(AT_FDCWD, "testfile_fopen_r+b", O_RDWR) = -1 ENOENT (No such file or directory) <0.000051>
// openat(AT_FDCWD, "testfile_fopen_rt+", O_RDWR) = -1 ENOENT (No such file or directory) <0.000037>
// openat(AT_FDCWD, "testfile_fopen_r+t", O_RDWR) = -1 ENOENT (No such file or directory) <0.000036>
	if (!strcmp(mode, "r+") || !strcmp(mode, "rb+") || !strcmp(mode, "r+b") ||
		!strcmp(mode, "rt+") || !strcmp(mode, "r+t"))
		return O_RDWR;

// these don't make sense, but whatever
// openat(AT_FDCWD, "testfile_fopen_rx", O_RDONLY|O_EXCL) = -1 ENOENT (No such file or directory) <0.000090>
// openat(AT_FDCWD, "testfile_fopen_rx+", O_RDWR|O_EXCL) = -1 ENOENT (No such file or directory) <0.000049>
	if (!strcmp(mode, "rx"))
		return O_RDONLY|O_EXCL;
	if (!strcmp(mode, "rx+"))
		return O_RDWR|O_EXCL;

// openat(AT_FDCWD, "testfile_fopen_w", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
// openat(AT_FDCWD, "testfile_fopen_wb", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
// openat(AT_FDCWD, "testfile_fopen_wt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
	if (!strcmp(mode, "w") || !strcmp(mode, "wb") || !strcmp(mode, "wt"))
		return O_WRONLY|O_CREAT|O_TRUNC;

// openat(AT_FDCWD, "testfile_fopen_w+", O_RDWR|O_CREAT|O_TRUNC, 0666) = 3
// openat(AT_FDCWD, "testfile_fopen_wb+", O_RDWR|O_CREAT|O_TRUNC, 0666) = 3
// openat(AT_FDCWD, "testfile_fopen_w+b", O_RDWR|O_CREAT|O_TRUNC, 0666) = 3
// openat(AT_FDCWD, "testfile_fopen_wt+", O_RDWR|O_CREAT|O_TRUNC, 0666) = 3
// openat(AT_FDCWD, "testfile_fopen_w+t", O_RDWR|O_CREAT|O_TRUNC, 0666) = 3
	if (!strcmp(mode, "w+") || !strcmp(mode, "wb+") || !strcmp(mode, "w+b") ||
		!strcmp(mode, "wt+") || !strcmp(mode, "w+t"))
		return O_RDWR|O_CREAT|O_TRUNC;

// openat(AT_FDCWD, "testfile_fopen_wx", O_WRONLY|O_CREAT|O_EXCL|O_TRUNC, 0666) = 3
	if (!strcmp(mode, "wx"))
		return O_WRONLY|O_CREAT|O_EXCL|O_TRUNC;

// openat(AT_FDCWD, "testfile_fopen_wx+", O_RDWR|O_CREAT|O_EXCL|O_TRUNC, 0666) = 3
	if (!strcmp(mode, "wx+"))
		return O_RDWR|O_CREAT|O_EXCL|O_TRUNC;

// openat(AT_FDCWD, "testfile_fopen_a", O_WRONLY|O_CREAT|O_APPEND, 0666) = 3
// openat(AT_FDCWD, "testfile_fopen_ab", O_WRONLY|O_CREAT|O_APPEND, 0666) = 3
// openat(AT_FDCWD, "testfile_fopen_at", O_WRONLY|O_CREAT|O_APPEND, 0666) = 3
	if (!strcmp(mode, "a") || !strcmp(mode, "ab") || !strcmp(mode, "at"))
		return O_WRONLY|O_APPEND|O_CREAT;

// openat(AT_FDCWD, "testfile_fopen_a+", O_RDWR|O_CREAT|O_APPEND, 0666) = 3
// openat(AT_FDCWD, "testfile_fopen_ab+", O_RDWR|O_CREAT|O_APPEND, 0666) = 3
// openat(AT_FDCWD, "testfile_fopen_a+b", O_RDWR|O_CREAT|O_APPEND, 0666) = 3
// openat(AT_FDCWD, "testfile_fopen_at+", O_RDWR|O_CREAT|O_APPEND, 0666) = 3
// openat(AT_FDCWD, "testfile_fopen_a+t", O_RDWR|O_CREAT|O_APPEND, 0666) = 3
	if (!strcmp(mode, "a+") || !strcmp(mode, "ab+") || !strcmp(mode, "a+b") ||
		!strcmp(mode, "at+") || !strcmp(mode, "a+t"))
		return O_RDWR|O_APPEND|O_CREAT;

// openat(AT_FDCWD, "testfile_fopen_ax", O_WRONLY|O_CREAT|O_EXCL|O_APPEND, 0666) = 3
	if (!strcmp(mode, "ax"))
		return O_WRONLY|O_CREAT|O_EXCL|O_APPEND;

// openat(AT_FDCWD, "testfile_fopen_ax+", O_RDWR|O_CREAT|O_EXCL|O_APPEND, 0666) = 3
	if (!strcmp(mode, "ax+"))
		return O_RDWR|O_CREAT|O_EXCL|O_APPEND;

	return 0; // we'll just decide to fail
}

FILE *fopen(const char *path, const char *mode) {
	FILE *ret = NULL;
	int fd;

	// successfully opened, or a different error occurred
	if ((ret = call_real(fopen, path, mode)) || errno != EUCLEAN)
		goto out;

	if ((fd = create_file_workaround(AT_FDCWD, path, fopen_mode_to_flags(mode), 0644)) >= 0) {
		ret = fdopen(fd, mode);
		errno = 0;
	}

out:
	return ret;
}

int mkdir(const char *path, mode_t mode) {
	return mkdirat_workaround(AT_FDCWD, path, mode);
}
int mkdirat(int dfd, const char *path, mode_t mode) {
	return mkdirat_workaround(dfd, path, mode);
}


int create_symlink_workaround(const char *path1, int dfd, const char *path2) {
	char *link_dir = NULL, *temp_link_dir = NULL, *temp_dirname = NULL;
	char *linkname = NULL, *temp_linkname = NULL;
	struct stat st;
	int ret = -1;

	get_real(symlinkat);

	link_dir = dirname2(path2);
	linkname = basename2(path2);

new_name:
	temp_dirname = make_tempname();

	asprintf(&temp_link_dir, "%s/%s", link_dir, temp_dirname);
	// check for the (unlikely) possibility we've got a dir entry by that obscure name
	if ((ret = fstatat(dfd, temp_link_dir, &st, AT_SYMLINK_NOFOLLOW)) == 0) {
		free_mem(temp_dirname);
		free_mem(temp_link_dir);
		goto new_name;
	}
	// make sure we failed because it didn't exist, not for some other reason
	if (errno != ENOENT)
		goto out;

	if ((ret = mkdirat_workaround(dfd, temp_link_dir, 0755)) < 0)
		goto out;

	asprintf(&temp_linkname, "%s/%s", temp_link_dir, linkname);

	if ((ret = call_real(symlinkat, path1, dfd, temp_linkname)) >= 0) {
		if ((renameat(dfd, temp_linkname, dfd, path2))) {
			unlinkat(dfd, temp_linkname, 0);
			unlinkat(dfd, temp_link_dir, AT_REMOVEDIR);
			ret = -1;
			goto out;
		}
		unlinkat(dfd, temp_link_dir, AT_REMOVEDIR);
#if DEBUG
		char dfd_str[10] = "AT_FDCWD";
		if (dfd != AT_FDCWD)
			snprintf(dfd_str, sizeof(dfd_str) - 1, "%d", dfd);
		output("worked around symlink creation for %s:'%s'\n",
			dfd_str, path2);
#endif
		goto out;
	} else {
		ret = -1;
		errno = EUCLEAN;
	}

out:
	free_mem(link_dir);
	free_mem(temp_link_dir);
	free_mem(temp_dirname);
	free_mem(linkname);
	free_mem(temp_linkname);

	return ret;
}
int symlink(const char *path1, const char *path2) {
	int ret;

        // successful symlink, or a different error occurred
	if (((ret = call_real(symlink, path1, path2)) >= 0) || errno != EUCLEAN)
		return ret;

	return create_symlink_workaround(path1, AT_FDCWD, path2);
}
int symlinkat(const char *path1, int dfd, const char *path2) {
	int ret;

        // successful symlink, or a different error occurred
	if (((ret = call_real(symlink, path1, path2)) >= 0) || errno != EUCLEAN)
		return ret;

	return create_symlink_workaround(path1, dfd, path2);
}

int create_special_workaround(int dfd, const char *path, mode_t mode, dev_t dev) {
	char *special_dir = NULL, *temp_special_dir = NULL, *temp_dirname = NULL;
	char *special_name = NULL, *temp_special_name = NULL;
	struct stat st;
	int ret = -1;

	special_dir = dirname2(path);
	special_name = basename2(path);

new_name:
	temp_dirname = make_tempname();

	asprintf(&temp_special_dir, "%s/%s", special_dir, temp_dirname);
	// check for the (unlikely) possibility we've got a dir entry by that obscure name
	if ((ret = fstatat(dfd, temp_special_dir, &st, AT_SYMLINK_NOFOLLOW)) == 0) {
		free_mem(temp_dirname);
		free_mem(temp_special_dir);
		goto new_name;
	}
	// make sure we failed because it didn't exist, not for some other reason
	if (errno != ENOENT)
		goto out;

	if ((ret = mkdirat_workaround(dfd, temp_special_dir, 0755)) < 0)
		goto out;

	asprintf(&temp_special_name, "%s/%s", temp_special_dir, special_name);

	if ((ret = call_real(mknodat, dfd, path, mode, dev)) >= 0) {
		if ((renameat(dfd, temp_special_name, dfd, path))) {
			unlinkat(dfd, temp_special_name, 0);
			unlinkat(dfd, temp_special_dir, AT_REMOVEDIR);
			ret = -1;
			goto out;
		}
		unlinkat(dfd, temp_special_dir, AT_REMOVEDIR);
#if DEBUG
		char dfd_str[10] = "AT_FDCWD";
		if (dfd != AT_FDCWD)
			snprintf(dfd_str, sizeof(dfd_str) - 1, "%d", dfd);
		output("worked around mknod creation for %s:'%s'\n",
			dfd_str, path);
#endif
		goto out;
	} else {
		ret = -1;
		errno = EUCLEAN;
	}

out:
	free_mem(special_dir);
	free_mem(temp_special_dir);
	free_mem(temp_dirname);
	free_mem(special_name);
	free_mem(temp_special_name);

	return ret;
}
int mknod(const char *path, mode_t mode, dev_t dev) {
	int ret;

	if (((ret = call_real(mknodat, AT_FDCWD, path, mode, dev)) >= 0) || errno != EUCLEAN)
		return ret;

	return create_special_workaround(AT_FDCWD, path, mode, dev);
}
int mknodat(int dfd, const char *path, mode_t mode, dev_t dev) {
	int ret;

	if (((ret = call_real(mknodat, dfd, path, mode, dev)) >= 0) || errno != EUCLEAN)
		return ret;

	return create_special_workaround(dfd, path, mode, dev);
}
int mkfifo(const char *path, mode_t mode) {
	int ret;

	if (((ret = call_real(mkfifo, path, mode)) >= 0) || errno != EUCLEAN)
		return ret;

	return create_special_workaround(AT_FDCWD, path, S_IFIFO|mode, 0);
}
int mkfifoat(int dfd, const char *path, mode_t mode) {
	int ret;

	if (((ret = call_real(mkfifoat, dfd, path, mode)) >= 0) || errno != EUCLEAN)
		return ret;

	return create_special_workaround(dfd, path, S_IFIFO|mode, 0);
}
