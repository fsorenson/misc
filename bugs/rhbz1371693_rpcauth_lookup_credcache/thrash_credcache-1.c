#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/capability.h>
#include <grp.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/fsuid.h>

#define UIDSKIPFREQ 5

#define KiB	(1024ULL)
#define MiB	(KiB * KiB)

#define GETDENTS_BUFSIZE	(64ULL * KiB)

#ifndef SYS_getdents64
#define SYS_getdents64 __NR_getdents64
#endif


#define likely(x)	__builtin_expect((x),1)
#define unlikely(x)	__builtin_expect((x),0)

#define exit_fail(args...) do { \
	printf("Error %d: %s - ", errno, strerror(errno)); \
	printf(args); exit(EXIT_FAILURE); } while (0)

struct linux_dirent64 {
	ino64_t		d_ino;
	off64_t		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[];
};

int recurse_stats(int base_dirfd, char *path) {
	struct linux_dirent64 *de;
	int nread;
	int dirfd;
	char *buf;
	char *bpos;
	struct stat st;
	int de_count = 0;

	buf = malloc(GETDENTS_BUFSIZE);
	if ((dirfd = openat(base_dirfd, path, O_RDONLY | O_DIRECTORY)) == -1)
		exit_fail("opening directory '%s'", path);

	for ( ;; ) {
		nread = syscall(SYS_getdents64, dirfd, buf, GETDENTS_BUFSIZE);
		if (unlikely(nread == 0))
			break;
		bpos = buf;
		while (bpos < buf + nread) {
			de = (struct linux_dirent64 *)bpos;

			if (likely(++de_count > 2)) {
				fstatat(dirfd, de->d_name, &st, 0);
				if (S_ISDIR(st.st_mode))
					recurse_stats(dirfd, de->d_name);
			}
			bpos += de->d_reclen;
		}
	}
	close(dirfd);
	free(buf);
	return 0;
}

int main(int argc, char *argv[]) {
	char *path;
	gid_t start_gid, end_gid;
	gid_t i;
	struct stat st;

	if (argc != 4) {
		printf("usage: %s <path> <start_gid> <end_gid>\n", argv[0]);
		return EXIT_FAILURE;
	}
	path = argv[1];
	start_gid = strtol(argv[2], NULL, 10);
	end_gid = strtol(argv[3], NULL, 10);

	printf("calling stat with various fsgids\n");
	for (i = start_gid ; i < end_gid ; i ++) {
		setfsgid(i);
//		setregid(-1, i);
//		recurse_stats(AT_FDCWD, path);
		stat(path, &st);
	}

	return EXIT_SUCCESS;
}
