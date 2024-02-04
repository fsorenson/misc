/*
	Frank Sorenson <sorenson@redhat.com>, 2022

	mkborken.c - program to reproduce an xfs filesystem containing a file
	having an inode number less than the inode number of the root directory
	of the filesystem.

	The resulting filesytem will reproduce the xfsdump bug found in
	Red Hat Bugzilla 2020494


	# gcc mkborken.c -o mkborken
	# ./mkborken <SIZE>

	for <size. #+[.[0-9]*][kmgtpe[ | b | ib ]]
	(case-insensitive, and all suffixes use base 1024)

	two directory entries will be created in the current directory:
		a filesystem image of <size>
		a subdirectory named 'mnt' on which the image will be mounted
	will run as root.  Otherwise, commands requiring root will be executed with 'sudo'
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <xfs/xfs.h>
#include <string.h>

#define KiB (1024UL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)
#define TiB (KiB * KiB * KiB * KiB)
#define PiB (KiB * KiB * KiB * KiB * KiB)
#define EiB (KiB * KiB * KiB * KiB * KiB * KiB)

#define MIN_IMAGE_SIZE (16UL * MiB)
#define MAX_IMAGE_SIZE (38UL * PiB)

#define XFS_SIZE_HOLE_MIN ((31UL*MiB) + 1UL)
#define XFS_SIZE_HOLE_MAX (32UL * MiB - 1)

#define MAX_IN_DIR (64UL)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define DIR_FMT "dir_%06" PRIu32
#define FILE_FMT "file_%06" PRIu64

#define VERBOSITY_QUIET	0
#define VERBOSITY_INFO	1
#define VERBOSITY_DEBUG	2

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

struct run_data {
	uint64_t image_size;
	uint64_t root_inum;
	uint64_t success_inum;

	uint32_t fsblock_size;
	uint32_t agcount;
	uint32_t agblocks;
	uint64_t datablocks;
	uint32_t ino_size;

	uint32_t dirs_created;
	uint32_t files_created;

	int verbosity; // potential TODO: command-line-configurable verbosity
	uid_t uid;
	gid_t gid;
	char *uid_gid;
	char *dirname;
	char *filename;

	char *success_path;
} run_data = {
	.image_size = -1,
	.root_inum = -1,
	.success_inum = -1,

	.fsblock_size = -1,
	.agcount = -1,
	.agblocks = -1,
	.datablocks = -1,
	.ino_size = -1,

	.dirs_created = 0,
	.files_created = 0,

	.verbosity = VERBOSITY_INFO,
	.uid_gid = NULL,
	.dirname = NULL,
	.filename = NULL,
	.success_path = NULL,
};

char *make_dirname(uint32_t i) {
	if (! run_data.dirname)
		asprintf(&run_data.dirname, DIR_FMT, run_data.agcount);

	sprintf(run_data.dirname, DIR_FMT, i);
	return run_data.dirname;
}
char *make_filename(uint64_t i) {
	if (! run_data.filename)
		asprintf(&run_data.filename, FILE_FMT, MAX_IN_DIR);

	sprintf(run_data.filename, FILE_FMT, i);
	return run_data.filename;
}

#define exec_cmd(msg_verbosity, args...) ({ \
	int ret = EXIT_FAILURE; \
	char *argv[] = { args, \
		NULL }; \
	char *newenv[] = { NULL }, **p = &argv[0]; \
	int cpid, status; \
\
	errno = 0; \
	if (run_data.verbosity + msg_verbosity >= VERBOSITY_DEBUG) { \
		output("executing command: "); \
		for (p = argv ; *p != NULL ; p++) \
			output(" %s", *p); \
		output("\n"); \
	} \
	if ((cpid = fork()) == 0) { \
		if (run_data.verbosity + msg_verbosity < VERBOSITY_INFO) { \
			int nullfd; \
			if ((nullfd = open("/dev/null", O_WRONLY)) < 0) { \
				output("Unable to open /dev/null: %m\n"); \
				exit(EXIT_FAILURE); \
			} \
			\
			dup3(nullfd, fileno(stdout), 0); \
			dup3(nullfd, fileno(stderr), 0); \
		} \
		execve(argv[0], argv, newenv); \
		exit(EXIT_FAILURE); /* should never happen, unless execve() fails */ \
	} \
	waitpid(cpid, &status, 0); \
	if (WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS) { \
		if (run_data.verbosity + msg_verbosity >= VERBOSITY_INFO) \
			output("child process exited with %d\n", WEXITSTATUS(status)); \
		ret = -WEXITSTATUS(status); \
	} else if (WIFSIGNALED(status)) { \
		output("child process exited with signal %d\n", WTERMSIG(status)); \
		switch (WTERMSIG(status)) { \
			case SIGSEGV: \
			case SIGBUS: \
				ret = -EFAULT; break; \
			case SIGINT: \
			case SIGTERM: \
			case SIGKILL: \
				ret = -EINTR; break; \
			default: \
				ret = -EAGAIN; break; \
		} \
	} else \
		ret = EXIT_SUCCESS; \
	ret; \
})
/* execve() the command with sudo, if we're not already root:root */
#define sudo_exec_cmd(msg_verbosity, args...) ({ \
	int ret = EXIT_FAILURE; \
\
	if (run_data.uid_gid) \
		ret = exec_cmd(msg_verbosity, "/usr/bin/sudo", args); \
	else \
		ret = exec_cmd(msg_verbosity, args); \
	ret; \
})

char *get_sunit_swidth_str(void) {
	if (run_data.image_size >= XFS_SIZE_HOLE_MIN && run_data.image_size < XFS_SIZE_HOLE_MAX) {
		char *str;
		asprintf(&str, "-dsize=%" PRIu64 ",sunit=256,swidth=256", XFS_SIZE_HOLE_MIN - 1);
		return str;
	}
	return strdup("-dsunit=2048,swidth=2048"); /* super-overkill, but it seems to work */
}

int mkfs(const char *device) {
	char *sunit_swidth_str = get_sunit_swidth_str();
	int ret = exec_cmd(VERBOSITY_INFO, "/usr/sbin/mkfs.xfs", "-f", sunit_swidth_str, (char *)device);
	free(sunit_swidth_str);
	return ret;
}
int sudo_mount(const char *device, const char *target) {
	return sudo_exec_cmd(VERBOSITY_QUIET, "/usr/bin/mount", (char *)device, (char *)target);
}
int sudo_umount(const char *mountpoint) {
	int ret = 0;

	ret = sudo_exec_cmd(VERBOSITY_INFO, "/usr/bin/umount", (char *)mountpoint);

	output("umount returned %d, errno: %d, %m\n", ret, errno);
	if (ret == EEXIST || errno == EEXIST)
		ret = 0;
	return ret == 0 ? 0 : errno;
}
int sudo_chown(const char *path, int uid, int gid) {
	if (run_data.uid_gid)
		return sudo_exec_cmd(VERBOSITY_QUIET, "/usr/bin/chown", run_data.uid_gid, (char *)path);
	else // no need to do anything
		return 0;
}

uint64_t get_inum(int dfd, const char *path) {
	struct statx stx;
	if ((statx(dfd, path, AT_EMPTY_PATH, STATX_INO, &stx)) < 0 ||
			!(stx.stx_mask & STATX_INO)) {
		output("error calling statx() on mountpoint: %m\n");
		return EXIT_FAILURE;
	}
	return stx.stx_ino;
}
#define P32(geo, s) do { \
	output("  %s: %" PRIu32 "\n", #s, geo.s); \
} while (0)
#define P64(geo, s) do { \
	output("  %s: %" PRIu64 "\n", #s, geo.s); \
} while (0)
#define P64b(geo, s) do { \
	output("  %s: %l" PRIu64 "\n", #s, geo.s); \
} while (0)
void get_fsgeo(int fd) {
	struct xfs_fsop_geom geo = { 0 };

	if (ioctl(fd, XFS_IOC_FSGEOMETRY, &geo)) { /* man xfsctl */
		output("error calling xfsctl: %m\n");
		exit(EXIT_FAILURE);
	}
	run_data.fsblock_size = geo.blocksize;
	run_data.agcount = geo.agcount;
	run_data.agblocks = geo.agblocks;
	run_data.datablocks = geo.datablocks;
	run_data.ino_size = geo.inodesize;

	if (run_data.verbosity >= VERBOSITY_INFO) {
		output("filesystem geometry:\n");
		P32(geo, version);
		P32(geo, sectsize);
		P32(geo, blocksize);
		P32(geo, dirblocksize);
		P32(geo, inodesize);
		P32(geo, agcount);
		P32(geo, agblocks);
		P32(geo, logblocks);
		P32(geo, sunit); /* size of a raid stripe in fsblocks */
		P32(geo, swidth); /* size of width of a raid stripe in sunits */
		P64b(geo, datablocks); /* requires an extra 'l' in the format string */
	}
}

int make_files(char *dir_path, int dfd) {
	uint64_t this_inum;
	int file_i, fd;

	for (file_i = 0 ; file_i < MAX_IN_DIR ; file_i++) {
		make_filename(file_i);
		if ((fd = openat(dfd, run_data.filename, O_CREAT|O_RDWR|O_TRUNC, 0644)) < 0) {
			output("error opening file %s/%s: %m\n",
				dir_path, run_data.filename);
			return EXIT_FAILURE;
		}
		this_inum = get_inum(fd, "");
		close(fd);
		if (this_inum < run_data.root_inum) {
			asprintf(&run_data.success_path, "%s/%s", dir_path, run_data.filename);
			run_data.success_inum = this_inum;
			return EXIT_SUCCESS;
		}
	}
	return EXIT_SUCCESS;
}
int make_subdirs(const char *base_path, int dfd) {
	int subdir_fd, dir_i = 0;
	uint64_t this_inum;
	char *subdir_path = NULL;

	asprintf(&subdir_path, "%s/%s", base_path, run_data.dirname);
	for (dir_i = 0 ; dir_i <= run_data.agcount ; dir_i++) {
		make_dirname(dir_i);
		sprintf(subdir_path, "%s/%s", base_path, run_data.dirname);

		if ((mkdirat(dfd, run_data.dirname, 0755)) < 0) {
			output("error creating subdir: %m\n");
			run_data.dirs_created = dir_i;
			run_data.files_created = 0;
			goto out;
		}
		this_inum = get_inum(dfd, run_data.dirname);
		if (this_inum < run_data.root_inum) {
			asprintf(&run_data.success_path, "%s/%s", subdir_path, run_data.dirname);
			run_data.success_inum = this_inum;
			goto out;
		}
		if ((subdir_fd = openat(dfd, run_data.dirname, O_RDONLY|O_DIRECTORY)) < 0) {
			output("error opening subdirectory: %m\n");
			run_data.dirs_created = dir_i + 1;
			run_data.files_created = 0;
			goto out;
		}

		if (dir_i % run_data.agcount == 0) /* only need to create files in directory[0] and directory[agcount] (the wraparound) */
			make_files(subdir_path, subdir_fd);

		close(subdir_fd);
		if (run_data.success_path)
			goto out;
	}
out:
	if (subdir_path)
		free(subdir_path);
	if (run_data.success_path)
		return EXIT_SUCCESS;
	return EXIT_FAILURE;
}

void cleanup(const char *mountpoint) {
	struct stat cwdst, mpst;

	if ((fstatat(AT_FDCWD, mountpoint, &mpst, 0)) < 0) {
		if (errno == ENOENT)
			mkdirat(AT_FDCWD, mountpoint, 0755);
	} else {
		if ((fstatat(AT_FDCWD, "", &cwdst, AT_EMPTY_PATH)) < 0) {
			output("could not stat current directory: %m\n");
			exit(EXIT_FAILURE);
		}
		if (cwdst.st_dev != mpst.st_dev) {
			if ((sudo_umount(mountpoint)) < 0) {
				output("couldn't unmount: %m\n");
				exit(EXIT_FAILURE);
			}
		}
	}
}
void make_img(const char *image) {
	int img_fd;

	output("creating image of size %" PRIu64 "...\n", run_data.image_size);
	if ((img_fd = openat(AT_FDCWD, image, O_RDWR|O_CREAT|O_TRUNC, 0644)) < 0) {
		output("error opening/creating image file '%s': %m\n", image);
		exit(EXIT_FAILURE);
	}
	if ((ftruncate(img_fd, run_data.image_size)) < 0) {
		output("error calling ftruncate(): %m\n");
		close(img_fd);
		exit(EXIT_FAILURE);
	}
	close(img_fd);

	if ((mkfs(image)) != 0) {
		output("error creating filesystem: %m\n");
		exit(EXIT_FAILURE);
	}
}
void mount_image(const char *image, const char *mountpoint) {
	if ((sudo_mount(image, mountpoint)) < 0) {
		output("error mounting: %m\n");
		exit(EXIT_FAILURE);
	}
}

/* returns a size in bytes */
/* accepts #+[.[0-9]*][kmgtpe[ | b | ib ]]  (case-insensitive) */
/* treats suffixes b B ib iB as base 1024 */
uint64_t parse_size(const char *size_str) {
	uint64_t size = 0, mult = 1;
	long double size_ld = 0;
	int shift = 0;
	char *p;

	if (strchr(size_str, '.')) /* try to deal with this as a float */
		size_ld = strtold(size_str, &p);
	else
		size = strtoull(size_str, &p, 10);

	while (*p != '\0' && (*p == '.' || *p == ' '))
		p++;
	if (*p != '\0') {
		if (strlen(p) <= 3) {
			if (strlen(p) == 2 && tolower(*(p+1)) != 'b')
				goto out_badsize;
			else if (strlen(p) == 3 &&
					(tolower(*(p+1)) != 'i' || tolower(*(p+2)) != 'b'))
				goto out_badsize;
			switch (tolower(*p)) {
				/* can't actually represent these */
				case 'y':
				case 'z':
					output("size too large: %s\n", p);
					return 0;
					break;;
				case 'e': shift++;
				case 'p': shift++;
				case 't': shift++;
				case 'g': shift++;
				case 'm': shift++;
				case 'k':
					shift++;
					break;;
				default:
					goto out;
					break;;
			}
		} else
			goto out_badsize;
	}
	if (shift)
		mult = 1ULL << (shift * 10);

	if (size)
		size *= mult;
	else if (size_ld != 0)
		size = (uint64_t)(size_ld * (long double)mult);
out:
	return size;

out_badsize:
	output("unrecognized size: '%s'\n", p);
	return 0;
}

int main(int argc, char *argv[]) {
	char *mountpoint = "mnt";
	char *image = "fsfile.img";
	int root_dfd;

	if (argc == 2) {
		run_data.image_size = parse_size(argv[1]);
		if (run_data.image_size == 0)
			return EXIT_FAILURE;
		if (run_data.image_size < MIN_IMAGE_SIZE) {
			output("image size '%" PRIu64 "' is too small; must be at least %" PRIu64 "\n",
				run_data.image_size, MIN_IMAGE_SIZE);
			return EXIT_FAILURE;
		}
		if (run_data.image_size > MAX_IMAGE_SIZE) {
			output("image size '%" PRIu64 "' is too large; cannot be larger than %" PRIu64 "\n",
			run_data.image_size, MAX_IMAGE_SIZE);
			return(EXIT_FAILURE);
		}
	} else {
		output("usage: %s <image_size>\n", argv[0]);
		output("\twhere <image_size> may be decimal or float, and may have a multiplier appended:\n");
		output("\t\tmultipliers: kmgtpe (may also have 'b' or 'ib' appended - base is always 1024\n");
		return EXIT_FAILURE;
	}

	run_data.uid = getuid();
	run_data.gid = getgid();
	if (run_data.uid != 0 || run_data.gid != 0) {
		asprintf(&run_data.uid_gid, "%d:%d", run_data.uid, run_data.gid);
	}

	output("cleaning up from any prior runs...\n");
	cleanup(mountpoint);

	make_img(image);
	mount_image(image, mountpoint);
	sudo_chown(mountpoint, run_data.uid, run_data.gid);

	if ((root_dfd = openat(AT_FDCWD, mountpoint, O_RDONLY|O_DIRECTORY)) < 0) {
		output("error opening directory for mountpoint: %m\n");
		return EXIT_FAILURE;
	}

	get_fsgeo(root_dfd);

	run_data.root_inum = get_inum(root_dfd, "");
	output("root inode: %" PRIu64 "\n", run_data.root_inum);

	make_subdirs(mountpoint, root_dfd);
	close(root_dfd);

	if (run_data.dirname)
		free(run_data.dirname);
	if (run_data.filename)
		free(run_data.filename);
	if (run_data.uid_gid)
		free(run_data.uid_gid);

	if (run_data.success_path) {
		output("found an inode number (%" PRIu64 ") less than root (%" PRIu64 ") for %s\n",
			run_data.success_inum, run_data.root_inum, run_data.success_path);
		free(run_data.success_path);
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}
