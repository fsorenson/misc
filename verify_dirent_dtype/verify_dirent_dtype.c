/*
	Frank Sorenson, <sorenson@redhat.com> 2018

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>

#define KiB (1024ULL)
#define BUF_SIZE (32ULL * KiB)

struct linux_dirent64 {
	ino64_t        d_ino;    /* 64-bit inode number */
	off64_t        d_off;    /* 64-bit offset to next structure */
	unsigned short d_reclen; /* Size of this dirent */
	unsigned char  d_type;   /* File type */
	char           d_name[]; /* Filename (null-terminated) */
};

char *stat_file_type_str(int t) {
	char *type;

	switch (t & S_IFMT) {
		case S_IFBLK: type = "BLK"; break;
		case S_IFCHR: type = "CHR"; break;
		case S_IFDIR: type = "DIR"; break;
		case S_IFIFO: type = "FIFO"; break;
		case S_IFLNK: type = "LINK"; break;
		case S_IFSOCK: type = "SOCK"; break;
		case S_IFREG: type = "REG"; break;
		default: type = "ERROR"; break;
	}
	return type;
}

void walk_path(const char *path);
static inline void walk_next_path(const char *path, const char *subdir) {
	char *new_path;
	asprintf(&new_path, "%s/%s", path, subdir);
	walk_path(new_path);
	free(new_path);
}

void walk_path(const char *path) {
	struct linux_dirent64 *temp_de;
	char *buf;
	struct stat st;
	int dir_fd;
	char *bpos;
	int nread;

	if ((dir_fd = open(path, O_RDONLY | O_DIRECTORY)) == -1) {
		printf("could not open directory '%s': %m\n", path);
		return;
	}

	buf = malloc(BUF_SIZE);
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

			printf("%s/%s:  getdents: %s", path, temp_de->d_name,
					stat_file_type_str(DTTOIF(temp_de->d_type)));

			if (fstatat(dir_fd, temp_de->d_name, &st, AT_SYMLINK_NOFOLLOW) == -1) {
				printf(", stat: ERROR: %m\n");
				if (temp_de->d_type == DT_DIR)
					walk_next_path(path, temp_de->d_name);
				continue;
			}

			printf(", stat: %s", stat_file_type_str(st.st_mode));

			if (DTTOIF(temp_de->d_type) != (st.st_mode & S_IFMT))
				printf(": ERROR\n");
			else
				printf("\n");

			if (temp_de->d_type == DT_UNKNOWN) {
				if (S_ISDIR(st.st_mode))
					walk_next_path(path, temp_de->d_name);
				continue;
			}

			if (S_ISDIR(DTTOIF(temp_de->d_type)) || S_ISDIR(st.st_mode))
				walk_next_path(path, temp_de->d_name);
		}
	}
	free(buf);
	close(dir_fd);
}

void start_walk_path(const char *path) {
	char *dpath = NULL;
	struct stat st;

	dpath = strdup(path);

	if (lstat(dpath, &st) == -1)
		printf("%s: error: %m\n", path);
	else if (S_ISDIR(st.st_mode))
		walk_path(dpath);

	free(dpath);
}

int main(int argc, char *argv[]) {
	int i;

	for (i = 1 ; i < argc ; i++)
		start_walk_path(argv[i]);
	return EXIT_SUCCESS;
}
