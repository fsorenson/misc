/*
	Frank Sorenson <sorenson@redhat.com>, 2019

	stat a file with nanosecond resolution

	operates recursively, if called on a directory

	# gcc -Wall stat_ns.c -o stat_ns

	$ ./stat_ns ~/.bash_profile
	/root/.bash_profile: mtime: 1584566602.193227569    ctime: 1584566602.204227568    atime: 1585686903.370420164
*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <errno.h>

#define KiB (1024ULL)
#define BUF_SIZE (32ULL * KiB)

#define NS_S (1000000000ULL)
#define NS_MS (1000000ULL)
#define NS_US (1000ULL)

#define DEBUG 0

static int have_statx = 1; /* for caching whether we have the stats syscall */

/* in case we have the syscall, but header files haven't caught up */
#ifndef SYS_statx
# define SYS_statx __NR_statx
# ifdef __i386__
#  define __NR_statx 383
# elif defined(__ILP32__)
#  define __NR_statx 383
# else
#  define __NR_statx 332
# endif
#endif

struct linux_dirent64 {
	ino64_t		d_ino;    /* 64-bit inode number */
	off64_t		d_off;    /* 64-bit offset to next structure */
	unsigned short	d_reclen; /* Size of this dirent */
	unsigned char	d_type;   /* File type */
	char		d_name[]; /* Filename (null-terminated) */
};

/* statx flags:
	AT_EMPTY_PATH
		if path is empty, operate on dfd
		if dfd is AT_FDCWD, operate on the current working directory
	AT_NO_AUTOMOUNT
		don't automount the final component of pathname if it is a directory that is an automount point
	AT_SYMLINK_NOFOLLOW
		don't follow symlink - provide info on the symlink itself
*/
/*
	STATX_TYPE          Want stx_mode & S_IFMT
	STATX_MODE          Want stx_mode & ~S_IFMT
	STATX_NLINK         Want stx_nlink
	STATX_UID           Want stx_uid
	STATX_GID           Want stx_gid
	STATX_ATIME         Want stx_atime

	STATX_MTIME         Want stx_mtime
	STATX_CTIME         Want stx_ctime
	STATX_INO           Want stx_ino
	STATX_SIZE          Want stx_size
	STATX_BLOCKS        Want stx_blocks
	STATX_BASIC_STATS   [All of the above]
	STATX_BTIME         Want stx_btime
	STATX_ALL           [All currently available fields]
*/
//struct statx_timestamp stx_btime;  /* Creation */
//struct statx_timestamp {
//	__s64 tv_sec;    /* Seconds since the Epoch (UNIX time) */
//	__u32 tv_nsec;   /* Nanoseconds since tv_sec */
//};

//int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);
static void do_fstatx(int dfd, const char *path) {
	struct statx stbuf;
	int ret;

	if ((ret = syscall(SYS_statx, dfd, path, AT_SYMLINK_NOFOLLOW, STATX_BTIME, &stbuf)) == 0) {
		printf("    btime: %lld.%09u", stbuf.stx_btime.tv_sec, stbuf.stx_btime.tv_nsec);
		return;
	}
	if (errno == ENOSYS)
		have_statx = 0;
	else
		printf("statx() failed with return code %d; error: %m\n", ret);
}

void print_stat(const char *path, const struct stat *st) {
	printf("%s: mtime: %ld.%09ld    ctime: %ld.%09ld    atime: %ld.%09ld",
		path, st->st_mtim.tv_sec, st->st_mtim.tv_nsec,
		st->st_ctim.tv_sec, st->st_ctim.tv_nsec,
		st->st_atim.tv_sec, st->st_atim.tv_nsec);

	if (have_statx)
		do_fstatx(AT_FDCWD, path);
	printf("\n");
}

int stat_tree(int dfd, const char *path) {
	struct linux_dirent64 *temp_de;
	int err_count = 0;
	struct stat st;
	char *newpath;
	char *bpos;
	char *buf;
	int nread;

	buf = malloc(BUF_SIZE);
	for (;;) {
		nread = syscall(SYS_getdents64, dfd, buf, BUF_SIZE);
		if (nread == -1 || nread == 0)
			goto out;
		bpos = buf;
		while (bpos < buf + nread) {
			temp_de = (struct linux_dirent64 *)bpos;
			bpos += temp_de->d_reclen;
			if ((!strcmp(temp_de->d_name, ".")) || (!strcmp(temp_de->d_name, "..")))
				continue;

			fstatat(dfd, temp_de->d_name, &st, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT);

			asprintf(&newpath, "%s/%s", path, temp_de->d_name);
			print_stat(newpath, &st);

			if (temp_de->d_type == DT_DIR) {
				int new_dfd;
				if ((new_dfd = openat(dfd, temp_de->d_name, O_NOFOLLOW | O_DIRECTORY)) < 0) {
					printf("unable to open path '%s': %m\n", newpath);
					err_count++;
				} else {
					err_count += stat_tree(new_dfd, newpath);
					close(new_dfd);
				}
			}
			free(newpath);
		}
	}
	free(buf);
out:
	return err_count;
}
int stat_tree_start(char *path) {
	int err_count = 0;
	struct stat st;
	int dfd;

	if (stat(path, &st) == -1) {
		printf("could not open path '%s': %m\n", path);
		err_count++;
		goto out;
	}
	print_stat(path, &st);
	if (S_ISDIR(st.st_mode)) {
		if ((dfd = open(path, O_RDONLY | O_DIRECTORY)) == -1) {
			printf("could not open directory '%s': %m\n", path);
			err_count++;
			goto out;
		}
		err_count += stat_tree(dfd, path);
	}
out:
	return err_count;
}
int usage(char *exe, int ret) {
	printf("usage: %s <path> [<path> ...]\n", exe);
	return ret;
}

int main(int argc, char *argv[]) {
	int err_count = 0;
	int i;

	if (argc < 2)
		return usage(argv[0], EXIT_SUCCESS);

	for (i = 1 ; i < argc ; i++)
		err_count = stat_tree_start(argv[i]);

	return err_count ? EXIT_FAILURE : EXIT_SUCCESS;
}
