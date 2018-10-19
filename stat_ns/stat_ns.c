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

#define KiB (1024ULL)
#define BUF_SIZE (32ULL * KiB)

#define NS_S (1000000000ULL)
#define NS_MS (1000000ULL)
#define NS_US (1000ULL)

#define DEBUG 0

struct linux_dirent64 {
	ino64_t		d_ino;    /* 64-bit inode number */
	off64_t		d_off;    /* 64-bit offset to next structure */
	unsigned short	d_reclen; /* Size of this dirent */
	unsigned char	d_type;   /* File type */
	char		d_name[]; /* Filename (null-terminated) */
};


#define ___PASTE(a,b)           a##b
#define ___PASTE3(a,b,c)        a##b##c

#define PASTE(a,b)            ___PASTE(a,b)
#define PASTE3(a,b,c)         ___PASTE3(a,b,c)

void print_stat(const char *path, const struct stat *st) {
	printf("%s: mtime: %ld.%09ld    ctime: %ld.%09ld    atime: %ld.%09ld\n",
		path, st->st_mtim.tv_sec, st->st_mtim.tv_nsec,
		st->st_ctim.tv_sec, st->st_ctim.tv_nsec,
		st->st_atim.tv_sec, st->st_atim.tv_nsec);
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

	for (i = 1 ; i < argc ; i++)
		err_count = stat_tree_start(argv[i]);

	return err_count ? EXIT_FAILURE : EXIT_SUCCESS;
}
