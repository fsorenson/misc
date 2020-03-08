#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sysmacros.h>

int main(int argc, char *argv[]) {
	struct stat st;

	if (argc == 2) {
		if ((fstatat(AT_FDCWD, argv[1], &st, AT_NO_AUTOMOUNT)) == 0) {
			printf("%s  dev: %ld:%ld  mode: %04o  inode: %ld  uid: %ld  gid: %ld\n",
				argv[1],
				(long)major(st.st_dev), (long)minor(st.st_dev),
				st.st_mode, st.st_ino, (long)st.st_uid, (long)st.st_gid);
			return EXIT_SUCCESS;
		}
	}
	return EXIT_FAILURE;
}
