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




int mkfiles(char *path, unsigned long count, uid_t uid, gid_t gid) {
	char filename[NAME_MAX + 1];
	int dirfd;
	int fd;
	unsigned long i;

	printf("making files\n");

	mkdir(path, 0755);
	dirfd = open(path, O_RDONLY | O_DIRECTORY);
	chown(path, uid, gid);
	for (i = 0 ; i < count ; ) {
		snprintf(filename, NAME_MAX, "test_file_%lu", i);
		fd = openat(dirfd, filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		fchown(fd, uid, gid);
		close(fd);
#if UIDSKIPFREQ
		if ((++i % UIDSKIPFREQ) == 0)
			uid++;
#endif
	}
	close(dirfd);

	return EXIT_SUCCESS;
}

int do_stats(char *path, unsigned long count) {
	char filename[NAME_MAX + 1];
	struct stat st;
	int dirfd;
	unsigned long i;

	printf("calling stat\n");
	dirfd = open(path, O_RDONLY | O_DIRECTORY);
	while (1) {
		for (i = 0 ; i < count ; i++) {
			snprintf(filename, NAME_MAX, "test_file_%lu", i);
			fstatat(dirfd, filename, &st, 0);
		}
	}
}

int recurse_stats(int base_dirfd, char *path) {
	struct linux_dirent64 *de;
	int nread;
	int dir_fd;
	char *buf;
	char *bpos;
	struct stat st;
	int de_count = 0;

	buf = malloc(GETDENTS_BUFSIZE);
	if ((dir_fd = openat(base_dirfd, path, O_RDONLY | O_DIRECTORY)) == -1)
		exit_fail("opening directory '%s'", path);

	for ( ;; ) {
		nread = syscall(SYS_getdents64, dir_fd, buf, GETDENTS_BUFSIZE);
		if (unlikely(nread == 0))
			break;
		bpos = buf;
		while (bpos < buf + nread) {
			de = (struct linux_dirent64 *)bpos;

			if (likely(++de_count > 2)) {
				fstatat(dir_fd, de->d_name, &st, 0);
				if (S_ISDIR(st.st_mode))
					recurse_stats(dir_fd, de->d_name);
			}
			bpos += de->d_reclen;
		}
	}
	close(dir_fd);
	free(buf);
	return 0;
}

int recurse0(char *path) {
	struct dirent *de, *p;
	DIR *dirp;
//	char *newpath;
	char newpath[NAME_MAX + 1];
	struct stat st;

	printf("recurse0(%s)\n", path);
	if ((dirp = opendir(path)) == NULL) {
		printf("%s: couldn't open path '%s': %m\n", __func__, path);
		return EXIT_FAILURE;
	}

	de = calloc(1, sizeof(struct dirent) + NAME_MAX + 1);

	do {
		if ((readdir_r(dirp, de, &p)) == 0) {
			if ((p == NULL) || (de == NULL))
				break;
			if ((de->d_name[0] == '.') &&
				((de->d_name[1] == '\0') ||
				((de->d_name[1] == '.') && (de->d_name[2] == '\0'))))
				continue;
			if ((de->d_type != DT_REG) && (de->d_type != DT_DIR))
				continue;

//			asprintf(&newpath, "%s/%s", path, de->d_name);
			snprintf(newpath, NAME_MAX + 1, "%s/%s", path, de->d_name);
//printf("round0: %s\n", newpath);

			stat(newpath, &st);
			if (de->d_type == DT_DIR)
				recurse0(newpath);
//			free(newpath);
		} else
			break;
	} while ((dirp != NULL) && (p != NULL));
	free(de);
	(void)closedir(dirp);

	return 0;
}

int recurse_chown(int base_dirfd, char *path, uid_t uid, gid_t gid) {
	struct linux_dirent64 *de;
	int nread;
	int dir_fd;
	char *buf;
	char *bpos;
	struct stat st;
	int de_count = 0;

	buf = malloc(GETDENTS_BUFSIZE);
	if ((dir_fd = openat(base_dirfd, path, O_RDONLY | O_DIRECTORY)) == -1)
		exit_fail("opening directory '%s'", path);

	for ( ;; ) {
		nread = syscall(SYS_getdents64, dir_fd, buf, GETDENTS_BUFSIZE);
		if (unlikely(nread == 0))
			break;
		bpos = buf;
		while (bpos < buf + nread) {
			de = (struct linux_dirent64 *)bpos;

			fchownat(dir_fd, de->d_name, uid, gid, 0);

			if (likely(++de_count > 2)) {
				fstatat(dir_fd, de->d_name, &st, 0);
				if (S_ISDIR(st.st_mode))
					recurse_chown(dir_fd, de->d_name, uid, gid);
			}
			bpos += de->d_reclen;
		}
	}
	close(dir_fd);
	free(buf);
	return 0;
}

int recurse1(char *path) {
	struct dirent *de, *p;
	DIR *dirp;
	char *newpath;

	printf("recurse1\n");
	if ((dirp = opendir(path)) == NULL) {
		printf("%s: couldn't open path '%s': %m\n", __func__, path);
		return EXIT_FAILURE;
	}

	de = calloc(1, sizeof(struct dirent) + NAME_MAX + 1);

	do {
		if ((readdir_r(dirp, de, &p)) == 0) {
			if ((p == NULL) || (de == NULL))
				break;
			if ((de->d_name[0] == '.') &&
				((de->d_name[1] == '\0') ||
				((de->d_name[1] == '.') && (de->d_name[2] == '\0'))))
				continue;
			if ((de->d_type != DT_REG) && (de->d_type != DT_DIR))
				continue;

			asprintf(&newpath, "%s/%s", path, de->d_name);
//printf("round1: %s\n", newpath);
			chmod(newpath, 0700);
			if (de->d_type == DT_DIR)
				recurse1(newpath);
			free(newpath);
		} else
			break;
	}while ((dirp != NULL) && (p != NULL));
	free(de);
	(void)closedir(dirp);

	return 0;
}
int recurse2(char *path) {
	struct dirent *de, *p;
	DIR *dirp;
	char *newpath;

	printf("recurse2(%s)\n", path);
	if ((dirp = opendir(path)) == NULL) {
		printf("%s: couldn't open path '%s': %m\n", __func__, path);
		return EXIT_FAILURE;
	}

	de = calloc(1, sizeof(struct dirent) + NAME_MAX + 1);

	do {
		if ((readdir_r(dirp, de, &p)) == 0) {
			if ((p == NULL) || (de == NULL))
				break;
			if ((de->d_name[0] == '.') &&
				((de->d_name[1] == '\0') ||
				((de->d_name[1] == '.') && (de->d_name[2] == '\0'))))
				continue;
			if ((de->d_type != DT_REG) && (de->d_type != DT_DIR))
				continue;

			asprintf(&newpath, "%s/%s", path, de->d_name);
//printf("round2: %s\n", newpath);
			if (de->d_type == DT_DIR) {
				recurse2(newpath);
				rmdir(newpath);
			} else
				unlink(newpath);
			free(newpath);
		} else
			break;
	}while ((dirp != NULL) && (p != NULL));
	free(de);
	(void)closedir(dirp);

	return 0;
}




int main(int argc, char *argv[]) {
	char *path = "/mnt/credcache/a/b/c";
	struct stat st;
	uid_t uid;
	gid_t gid;
	cap_t caps;
	cap_value_t cap_list;
	int i;


	stat(path, &st);
	uid = st.st_uid;
	gid = st.st_gid;

//	mkfiles("/mnt/credcache/a/b/c/somesubdir", 10000, 500, 500);

	printf("calling stat with various fsgids\n");
	for (i = 500 ; i < 100000 ; i ++) {
//		setfsuid(i);
		setfsgid(i);
		recurse_stats(AT_FDCWD, "/mnt/credcache/a/b/c/somesubdir");
	}

	return 0;


	printf("doing some chownage()\n");

	for (i = 500 ; i < 1000 ; i ++) {
		recurse_chown(AT_FDCWD, "/mnt/credcache/a/b/c/somesubdir", i, -1);
	}
	recurse_chown(AT_FDCWD, "/mnt/credcache/a/b/c/somesubdir", 500, 500);



	seteuid(uid);

	// cap_t cap_get_proc(void);
	caps = cap_get_proc();
	cap_list = CAP_SYS_CHROOT;
	// int cap_set_flag(cap_t cap_p, cap_flag_t flag, int ncap, const cap_value_t *caps, cap_flag_value_t value);
	cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap_list, CAP_SET);

	chroot(path);
	chdir("/");

	seteuid(uid);
	setgid(gid);
	setgroups(0, 0);
	setuid(uid);

//	do_stats("somesubdir", 100000);

//	while (1) {
		recurse0("somesubdir");
//	}


//	while (1) {
//		recurse1("somesubdir");
//	}

//	recurse_chown(AT_FDCWD, "somesubdir", 500, 500);
//	recurse_chown("somesubdir", 500);
	recurse1("somesubdir");
	recurse2("somesubdir");

	return EXIT_FAILURE;
}
