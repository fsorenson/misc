#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>

#define INDENT "  "
#define KiB (1024ULL)
#define BUF_SIZE (32ULL * KiB)

#define NS_S (1000000000ULL)
#define NS_MS (1000000ULL)
#define NS_US (1000ULL)

#define OK_STRING "_"
#define BAD_STRING "*"


#define DEBUG 0


static int tzoffset_secs;


struct linux_dirent64 {
	ino64_t		d_ino;    /* 64-bit inode number */
	off64_t		d_off;    /* 64-bit offset to next structure */
	unsigned short	d_reclen; /* Size of this dirent */
	unsigned char	d_type;   /* File type */
	char		d_name[]; /* Filename (null-terminated) */
};

typedef void (*check_path_func_t)(const char *path, const struct stat *st);
static check_path_func_t check_path;
static int is_vfat = 1;

int ctime_okay_vfat(struct timespec ts) {
	if (ts.tv_nsec) {
		if (is_vfat) {
//			if ( (ts.tv_nsec / NS_MS) % 10) {
			if (ts.tv_nsec % (NS_MS * 10)) {
#if DEBUG
				printf(INDENT INDENT "***** ctime invalid for vfat: %ld.%09ld\n",
					ts.tv_sec, ts.tv_nsec);
#endif
			} else
				return 1;
		} else
#if DEBUG
			printf(INDENT "***** ctime invalid: %ld.%09ld, tv_nsec nonzero\n",
				ts.tv_sec, ts.tv_nsec);
#else
			;
#endif
		return 0;
	}
	return 1;
}
int mtime_okay_vfat(struct timespec ts) {
	if (ts.tv_sec & 1 || ts.tv_nsec) {
#if DEBUG
		printf(INDENT "***** mtime invalid: %ld.%09ld",
			ts.tv_sec, ts.tv_nsec);
		printf("%s", ts.tv_nsec ? ", tv_nsec nonzero\n" : "\n");
#endif
		return 0;
	}
	return 1;
}
int atime_okay_vfat(struct timespec ts) {
	if (ts.tv_nsec)
		return 0;
	ts.tv_sec -= tzoffset_secs;
	if (ts.tv_sec % 86400 || ts.tv_nsec) {
#if DEBUG
		printf(INDENT "***** atime invalid: %ld.%09ld, remainder: %ld",
			ts.tv_sec, ts.tv_nsec, ts.tv_sec % 86400);
		printf("%s", ts.tv_nsec ? ", tv_nsec nonzero\n" : "\n");
#endif
		return 0;
	}
	return 1;
}
int check_root_tstamp(struct timespec ts) {
	return !(ts.tv_sec || ts.tv_nsec);
}
#define check_root_tstamp_vfat(ts) (check_root_tstamp(ts))

#define ___PASTE(a,b)           a##b
#define ___PASTE3(a,b,c)        a##b##c

#define PASTE(a,b)            ___PASTE(a,b)
#define PASTE3(a,b,c)         ___PASTE3(a,b,c)

#define check_okay_vfat(st, time_type) do { \
	int okay = 1; \
	if (st->st_ino == 1) \
		okay = check_root_tstamp_vfat(st-> PASTE3(st_,time_type,tim)); \
	else \
		okay = PASTE(time_type, time_okay_vfat)(st->PASTE3(st_, time_type, tim)); \
	PASTE(time_type, _str) = okay ? OK_STRING : BAD_STRING; \
} while (0)

//void check_tree(int dfd, const char *path);
void check_path_vfat(const char *path, const struct stat *st) {
	int m, c, a;
	m = c = a = 1;

	if (st->st_ino == 1) {
		if (st->st_mtim.tv_sec || st->st_mtim.tv_nsec)
			m = 0;
		if (st->st_ctim.tv_sec || st->st_ctim.tv_nsec)
			c = 0;
		if (st->st_atim.tv_sec || st->st_atim.tv_nsec)
			a = 0;
	} else {
		m = mtime_okay_vfat(st->st_mtim);
		c = ctime_okay_vfat(st->st_ctim);
		a = atime_okay_vfat(st->st_atim);
	}

	printf(INDENT "%s mtime: %ld.%09ld  %s ctime: %ld.%09ld  %s atime: %ld.%09ld  %s\n",
		m ? OK_STRING : BAD_STRING, st->st_mtim.tv_sec, st->st_mtim.tv_nsec,
		c ? OK_STRING : BAD_STRING, st->st_ctim.tv_sec, st->st_ctim.tv_nsec,
		a ? OK_STRING : BAD_STRING, st->st_atim.tv_sec, st->st_atim.tv_nsec,
		path);
}
void check_path_msdos(const char *path, const struct stat *st) {
	int m, c, a;
	m = c = a = 1;

	if (st->st_ino == 1) {
		if (st->st_mtim.tv_sec || st->st_mtim.tv_nsec)
			m = 0;
		if (st->st_ctim.tv_sec || st->st_ctim.tv_nsec)
			c = 0;
		if (st->st_atim.tv_sec || st->st_atim.tv_nsec)
			a = 0;
	} else {
		if (st->st_mtim.tv_sec & 1 || st->st_mtim.tv_nsec) {
			m = c = a = 0;
		} else {
			if (st->st_ctim.tv_sec != st->st_mtim.tv_sec || st->st_ctim.tv_nsec)
				c = 0;
//			if (st->st_atim.tv_sec != st->st_mtim.tv_sec || st->st_atim.tv_nsec)
//				a = 0;
			a = atime_okay_vfat(st->st_atim);
		}
	}

	printf(INDENT "%s mtime: %ld.%09ld  %s ctime: %ld.%09ld  %s atime: %ld.%09ld  %s\n",
		m ? OK_STRING : BAD_STRING, st->st_mtim.tv_sec, st->st_mtim.tv_nsec,
		c ? OK_STRING : BAD_STRING, st->st_ctim.tv_sec, st->st_ctim.tv_nsec,
		a ? OK_STRING : BAD_STRING, st->st_atim.tv_sec, st->st_atim.tv_nsec,
		path);
}

int check_tree(int dfd, const char *path) {
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
			check_path(newpath, &st);

			if (temp_de->d_type == DT_DIR) {
				int new_dfd;
				if ((new_dfd = openat(dfd, temp_de->d_name, O_NOFOLLOW | O_DIRECTORY)) < 0) {
					printf("unable to open path '%s': %m\n", newpath);
					err_count++;
				} else {
					err_count += check_tree(new_dfd, newpath);
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
int check_tree_start(char *path) {
	int err_count = 0;
	struct stat st;
	int dfd;

	if (stat(path, &st) == -1) {
		printf("could not open path '%s': %m\n", path);
		err_count++;
		goto out;
	}
	check_path(path, &st);
	if (S_ISDIR(st.st_mode)) {
		if ((dfd = open(path, O_RDONLY | O_DIRECTORY)) == -1) {
			printf("could not open directory '%s': %m\n", path);
			err_count++;
			goto out;
		}
		err_count += check_tree(dfd, path);
	}
out:
	return err_count;
}
int usage(char *exe, int ret) {
	printf("usage: %s <vfat | msdos> <path> [<path> ...]\n", exe);
	return ret;
}

int main(int argc, char *argv[]) {
	struct timezone tz;
	struct timeval tv;
	int err_count = 0;
	int i;

	gettimeofday(&tv, &tz);
	tzoffset_secs = tz.tz_minuteswest * 60;

	if (argc < 3)
		return usage(argv[0], EXIT_FAILURE);

	if (!strcmp(argv[1], "vfat"))
		is_vfat = 1;
	else if (!strcmp(argv[1], "msdos"))
		is_vfat = 0;
	else
		return usage(argv[0], EXIT_FAILURE);

	if (is_vfat)
		check_path = check_path_vfat;
	else
		check_path = check_path_msdos;

	printf("using '%s' rules\n", is_vfat ? "vfat" : "msdos");

	for (i = 2 ; i < argc ; i++)
		err_count = check_tree_start(argv[i]);

	return err_count ? EXIT_FAILURE : EXIT_SUCCESS;
}
