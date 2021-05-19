/*

	Frank Sorenson <sorenson@redhat.com>, 2021

	nfs4_showmount-e.c - an nfsv4-equivalent to 'showmount -e'

	since nfs v4 exports just a root '/', but may have other filesystems
	mounted beneath the root, this determines what those filesystems
	are and outputs the path and filesystem id.  subdirectories with
	on the same device as the root are not shown.

	# ./nfs4_showmount-e vm3
	exported by vm3
	    /	fsid: 0:0
	    /mnt2	fsid: c10a1819257f4d4d:a0d6372e2f44b4e3
	    /mnt	fsid: c10a1819257f4d4d:a0d6372e2f44b4e3
	    /mnt1	fsid: c10a1819257f4d4d:a0d6372e2f44b4e3


	*** requires root privileges, since the filesystem root must be mounted ***

	*** only supports 'sec=sys' at this time (2021) ***
	*** does not search subdirectories of the root for other mounts ***
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define KiB (1024ULL)
#define MiB (KiB * KiB)

#define BUF_SIZE (32ULL * KiB)

#define free_str(a) do { if (a) { free(a); a = NULL; } } while (0)

struct fsent {
	char *fsid;
	char *path;
};

struct fsent *get_fsid(dev_t search_dev) {
//	struct fsent *fsent = malloc(sizeof(struct fsent));
	struct fsent *fsent = NULL;
	char *dev = NULL, *fsid = NULL;
	int fd, nread;
	FILE *file;

//	printf("searching for %d:%d\n", major(search_dev), minor(search_dev));

	if ((fd = open("/proc/fs/nfsfs/volumes", O_RDONLY)) < 0) {
		printf("unable to determine fsid: %m\n");
		exit(-1);
	}
	file = fdopen(fd, "r");

	if ((nread = fscanf(file, "%*s %*s %*s %*s %*s %*s")) < 0) {
		printf("uhm: %m\n");
		exit(1);
	}
	while ((nread = fscanf(file, "%*s %*s %*s %ms %ms %*s", &dev, &fsid)) != EOF) {
		int maj, min;
		char *p;

		maj = strtol(dev, &p, 10);
		if (!errno && *p == ':')
			min = strtol(p + 1, NULL, 10);
		if (errno || *p != ':') {
			printf("could not parse '%s': %m\n", dev);
		} else {
//printf("  parsed '%s' to %d:%d (for fsid '%s')\n", dev, maj, min, fsid);
			if (search_dev == makedev(maj, min)) {
//				printf("fsid: %s", fsid);

//		if ((nread = fscanf(file, "%*s %*s %*s %ms %ms %*s", &dev, &fsid)) != 2) {
//			printf("read %d instead of 2: %m\n", nread);
//			exit(2);
//		}

//NV SERVER   PORT DEV          FSID                              FSC
//v4 c0a87a47  801 0:50         0:0                               no 
//v4 c0a87a47  801 0:51         c10a1819257f4d4d:a0d6372e2f44b4e3 no 

				fsent = malloc(sizeof(struct fsent));
				fsent->fsid = strdup(fsid);

				goto out;			

				break;
			}
//			printf(" dev: %s - fsid: %s\n", dev, fsid);
		}
		free_str(dev);
		free_str(fsid);
	}

out:
	free_str(dev);
	free_str(fsid);
	close(fd);

	return fsent;
}

int try_mount(const char *server, const char *server_addr_str, const char *mount_path) {
	char *mountopts_str = NULL, *source = NULL;
	int ret = EXIT_SUCCESS;
	int nfsv4_minor;

	asprintf(&source, "%s:/", server);
	asprintf(&mountopts_str, "vers=4.0,sec=sys,addr=%s", server_addr_str);
//	mountopts_str = strdup("vers=4.0,sec=sys,addr=%s", server_addr_str);

	for (nfsv4_minor = 2 ; nfsv4_minor >= 0 ; nfsv4_minor--) {
		snprintf(mountopts_str, strlen(mountopts_str) + 1, "vers=4.%d,sec=sys,addr=%s", nfsv4_minor, server_addr_str);

		if (! mount(source, mount_path, "nfs", MS_NOATIME|MS_NODEV|MS_NOEXEC|MS_NOSUID|MS_RDONLY, 
			mountopts_str)) {
//			printf("mounted %s\n", source);
			goto out;
		}
	}
	ret = EXIT_FAILURE;

out:
	free_str(mountopts_str);
	free_str(source);
	return ret;
}

int list_subdirs(const char *server_name, const char *path) {
	int ret = EXIT_FAILURE;
	struct dirent *de;
	char *buf = NULL, *tmp_path = NULL;
	int dfd = -1, nread;
	struct statvfs stvfs;
	struct stat st;
	dev_t root_dev;
	unsigned long root_fsid;
	struct fsent *fsent;


	if ((dfd = open(path, O_RDONLY|O_DIRECTORY)) < 0) {
		printf("could not open mounted directory: %m\n");
		goto out;
	}

	buf = malloc(BUF_SIZE);
	tmp_path = malloc(PATH_MAX);

	snprintf(tmp_path, PATH_MAX, "%s/", path);

//	printf("%s - ", tmp_path);
	if (statvfs(tmp_path, &stvfs) < 0) {
		printf("unable to statvfs(%s): %m\n", tmp_path);
	} else {
		root_fsid = stvfs.f_fsid;
//		printf("fsid: %lu, ", stvfs.f_fsid);
	}
	if (stat(tmp_path, &st) < 0) {
		printf("unable to stat(%s): %m\n", tmp_path);
	} else {
		root_dev = st.st_dev;
//		printf("dev: %d:%d\n", major(st.st_dev), minor(st.st_dev));
	}



	while (42) {
		char *bpos = buf;

		if ((nread = syscall(SYS_getdents64, dfd, buf, BUF_SIZE)) < 0) {
			printf("error calling getdents64(): %m\n");
			goto out;
		}
		if (nread == 0)
			break;
		while (bpos < buf + nread) {
#if 0
           struct statvfs {
               unsigned long  f_bsize;    /* Filesystem block size */
               unsigned long  f_frsize;   /* Fragment size */
               fsblkcnt_t     f_blocks;   /* Size of fs in f_frsize units */
               fsblkcnt_t     f_bfree;    /* Number of free blocks */
               fsblkcnt_t     f_bavail;   /* Number of free blocks for
                                             unprivileged users */
               fsfilcnt_t     f_files;    /* Number of inodes */
               fsfilcnt_t     f_ffree;    /* Number of free inodes */
               fsfilcnt_t     f_favail;   /* Number of free inodes for
                                             unprivileged users */
               unsigned long  f_fsid;     /* Filesystem ID */
               unsigned long  f_flag;     /* Mount flags */
               unsigned long  f_namemax;  /* Maximum filename length */
           };
#endif

			de = (struct dirent *)bpos;
			bpos += de->d_reclen;

			if ((DTTOIF(de->d_type) & S_IFMT) == S_IFDIR) {
				if (!strcmp(de->d_name, ".."))
					continue;

				snprintf(tmp_path, PATH_MAX, "%s/%s/", path, de->d_name);

//				printf("%s - ", tmp_path);
//				printf("%s:/%s - ", server_name, de->d_name);

				if (statvfs(tmp_path, &stvfs) < 0) {
					printf("unable to statvfs(%s): %m\n", tmp_path);
					continue;
				}
//				printf("fsid: %lu, ", stvfs.f_fsid);
				if (stat(tmp_path, &st) < 0) {
					printf("unable to stat(%s): %m\n", tmp_path);
					continue;
				}

				if (st.st_dev == root_dev && strcmp(de->d_name, "."))
					continue;

				if ((fsent = get_fsid(st.st_dev)) != NULL) {
					if (!strcmp(de->d_name, "."))
						fsent->path = strdup("/");
					else
						asprintf(&fsent->path, "/%s", de->d_name);


//					printf("dev: %d:%d, ", major(st.st_dev), minor(st.st_dev));
					printf("    %s\tfsid: %s", fsent->path, fsent->fsid);

					free_str(fsent->path);
					free_str(fsent->fsid);
					free_str(fsent);
				} else
					printf("    %s\tcould not find fsid", de->d_name);
				printf("\n");

				if (st.st_dev != root_dev || stvfs.f_fsid != root_fsid) {
					int retries = 5;
umount_subdir:
					if (umount(tmp_path) < 0) {
						printf("unable to unmount %s: %m\n", tmp_path);
						if (retries-- > 0)
							goto umount_subdir;
						sleep(1);
					}
				}

			}
		}

	}


	ret = EXIT_SUCCESS;
out:
	free_str(tmp_path);
	free_str(buf);

	if (dfd >= 0)
		close(dfd);

	return ret;
}

int fill_ipv4_sockaddr(const char *hostname, struct sockaddr_in *addr) {
	struct hostent *he;
	addr->sin_family = AF_INET;

	if (inet_aton(hostname, &addr->sin_addr))
		return 0;
	if ((he = gethostbyname(hostname)) == NULL) {
		printf("could not get address for %s: %m\n", hostname);
		return -1;
	}
	if (he->h_length > sizeof(struct in_addr)) {
		printf("host length too long\n");
		he->h_length = sizeof(struct in_addr);
	}
	memcpy(&addr->sin_addr, he->h_addr, he->h_length);
	return 0;
}


int main(int argc, char *argv[]) {
	char *mount_dir = NULL;
	int ret = EXIT_FAILURE;
	struct sockaddr_in server_addr;
	char *server_name, *server_addr_str = NULL;

	if (argc != 2) {
		printf("usage: %s <server>\n", argv[0]);
		goto out;
	}
	server_name = argv[1];

	if (fill_ipv4_sockaddr(server_name, &server_addr) == EXIT_FAILURE)
		goto out;

	server_addr_str = strdup(inet_ntoa(server_addr.sin_addr));


	mount_dir = strdup("/tmp/tmp_mount.XXXXXX");

	if (!mkdtemp(mount_dir)) {
		printf("unable to create temp directory: %m\n");
		goto out;
	}

//	if (try_mount(server_name, mount_dir) == EXIT_SUCCESS) {
	if (try_mount(server_name, server_addr_str, mount_dir) == EXIT_SUCCESS) {
		int retries = 5;

		printf("exported by %s\n", server_name);
		list_subdirs(server_name, mount_dir);


umount_root:
		if (umount(mount_dir) < 0) {
			printf("unable to unmount %s: %m\n", mount_dir);
			if (retries-- > 0)
				goto umount_root;
			sleep(1);
		}

		ret = EXIT_SUCCESS;
	} else {
		printf("unable to mount server '%s:/': %m\n", server_name);
	}
out:
	free_str(mount_dir);
	free_str(server_addr_str);

	return ret;
}

