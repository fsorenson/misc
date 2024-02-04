#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
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

#define FSBLOCK_SIZE (4096UL)
#define EXPECTED_AGS (4UL)
#define IMAGE_SIZE (256UL * KiB * FSBLOCK_SIZE)
#define FILE_BLOCKS (0UL)
//#define IMAGE_SIZE (268088377344UL)

#define MKFS_XFS_ARGS , "-mreflink=0,rmapbt=0,finobt=1", "-isparse=0"

#define CREATE_SUBDIRS 1
#define ADD_FILLER 0

//#define MAX_DIRS (128UL)
//#define MAX_IN_DIR (256UL)
#define MAX_DIRS (8192UL)
//#define MAX_IN_DIR (256UL)
#define MAX_IN_DIR (64UL)

#define AG_BLOCKS(img_sz, expected_ags, block_sz) (img_sz / expected_ags / block_sz)

//
//#define IMAGE_SIZE (((512UL*1024UL) + 16248UL - 440UL + 256UL + 128UL + 1UL) * 4096UL)
//#define IMAGE_SIZE (((512UL*1024UL) + 16248UL) * 4096UL )


#define SUNIT , "-dsunit=256,swidth=256"

#if 0
#undef IMAGE_SIZE
#undef EXPECTED_AGS
#undef SUNIT
#define IMAGE_SIZE (32UL * MiB)
#define EXPECTED_AGS (2UL)
#define SUNIT
#endif

#if 0
#undef IMAGE_SIZE
#undef EXPECTED_AGS
#undef SUNIT
#define IMAGE_SIZE (2162432UL * FSBLOCK_SIZE)
#define EXPECTED_AGS (4UL)
#define SUNIT
#endif

#if 0 // an attempt from mkborken2
#undef IMAGE_SIZE
#undef EXPECTED_AGS
#define IMAGE_SIZE (2213810176UL)
#define EXPECTED_AGS (4UL)
#endif


// sz4 in borken - working
#if 1
#undef IMAGE_SIZE
#undef EXPECTED_AGS
#undef SUNIT
#undef FILE_BLOCKS
#define IMAGE_SIZE (10UL * TiB) // requires no filler .. just 61 files
#define EXPECTED_AGS (32UL)
#define SUNIT , "-dsunit=256,swidth=256"
#define FILE_BLOCKS (0UL)
#endif

// sz4 in borken modified - working)
#if 1
#undef IMAGE_SIZE
#undef EXPECTED_AGS
#undef SUNIT
#undef FILE_BLOCKS
#define IMAGE_SIZE (5UL * TiB)
#define EXPECTED_AGS (32UL)
#define SUNIT , "-dsunit=256,swidth=256"
#define FILE_BLOCKS (0UL)
#endif


// sz4 in borken modified - working)
#if 1
#undef IMAGE_SIZE
#undef EXPECTED_AGS
#undef SUNIT
#undef FILE_BLOCKS
#define IMAGE_SIZE (10UL * GiB)
#define EXPECTED_AGS (32UL)
#define SUNIT , "-dsunit=256,swidth=256"
//#define SUNIT , "-dsunit=512,swidth=512"
#define FILE_BLOCKS (0UL)
#endif


#if 0
// sz5 in borken2?
#undef IMAGE_SIZE
#undef EXPECTED_AGS
//#define IMAGE_SIZE (268088377344UL)
#endif



//#undef SUNIT
//#define SUNIT , "-dsunit=128,swidth=128"



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

	.uid_gid = NULL,
	.dirname = NULL,
	.filename = NULL,
	.success_path = NULL,
};
#define DIR_FMT "dir_%06" PRIu64
#define FILE_FMT "file_%06" PRIu64

char *make_dirname(uint64_t i) {
	if (! run_data.dirname)
		asprintf(&run_data.dirname, DIR_FMT, MAX_DIRS);

	sprintf(run_data.dirname, DIR_FMT, i);
	return run_data.dirname;
}
char *make_filename(uint64_t i) {
	if (! run_data.filename)
		asprintf(&run_data.filename, FILE_FMT, MAX_IN_DIR);

	sprintf(run_data.filename, FILE_FMT, i);
	return run_data.filename;
}


#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define exec_cmd(quiet, args...) ({ \
	int ret = EXIT_FAILURE; \
	int cpid, status; \
\
	errno = 0; \
	if ((cpid = fork()) == 0) { \
		char *argv[] = { args, NULL }; \
		char *newenv[] = { NULL }; \
		\
		execve(argv[0], argv, newenv); \
		exit(EXIT_FAILURE); /* should never happen, unless execve() fails */ \
	} \
	waitpid(cpid, &status, 0); \
	if (WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS) { \
		if (!quiet) \
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
#define sudo_exec_cmd(quiet, args...) ({ \
	int ret = EXIT_FAILURE; \
\
	if (run_data.uid_gid) \
		ret = exec_cmd(quiet, "/usr/bin/sudo", args); \
	else \
		ret = exec_cmd(quiet, args); \
	ret; \
})

int mkfs(const char *device) {
	return exec_cmd(false, "/usr/sbin/mkfs.xfs", "-f" MKFS_XFS_ARGS SUNIT, (char *)device);
//	return exec_cmd(false, "/usr/sbin/mkfs.xfs", "-f", "-dsunit=256,swidth=256", (char *)device);
}
int sudo_mount(const char *device, const char *target) {
/*
	if (run_data.uid_gid)
		return exec_cmd(false, "/usr/bin/sudo", "/usr/bin/mount", (char *)device, (char *)target);
	else
		return exec_cmd(false, "/usr/bin/mount", (char *)device, (char *)target);
*/
	return sudo_exec_cmd(false, "/usr/bin/mount", (char *)device, (char *)target);
}
int sudo_umount(const char *mountpoint, bool quiet) {
	int ret = 0;
/*
	if (run_data.uid_gid)
		ret = exec_cmd(quiet, "/usr/bin/sudo", "/usr/bin/umount", (char *)mountpoint);
	else
		ret = exec_cmd(quiet, "/usr/bin/umount", (char *)mountpoint);
*/
	ret = sudo_exec_cmd(quiet, "/usr/bin/umount", (char *)mountpoint);

	output("umount returned %d, errno: %d, %m\n", ret, errno);
	if (ret == EEXIST || errno == EEXIST)
		ret = 0;
	return ret == 0 ? 0 : errno;
}
int sudo_chown(const char *path, int uid, int gid) {
	if (run_data.uid_gid)
		return sudo_exec_cmd(false, "/usr/bin/chown", run_data.uid_gid, (char *)path);
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
void get_fsgeo(int fd) {
	struct xfs_fsop_geom geo = { 0 };

//	if (xfsctl("", fd, XFS_IOC_FSGEOMETRY, &geo)) {
	if (ioctl(fd, XFS_IOC_FSGEOMETRY, &geo)) {
		output("error calling xfsctl: %m\n");
		exit(EXIT_FAILURE);
	}
	run_data.fsblock_size = geo.blocksize;
	run_data.agcount = geo.agcount;
	run_data.agblocks = geo.agblocks;
	run_data.datablocks = geo.datablocks;
	run_data.ino_size = geo.inodesize;
}
/*
           struct xfs_fsop_geom {
                __u32         blocksize; // in bytes
                __u32         rtextsize; // in bytes
                __u32         agblocks; // in fsblocks
                __u32         agcount;
                __u32         logblocks; // in fsblocks
                __u32         sectsize; // in bytes
                __u32         inodesize; // in bytes
                __u32         imaxpct; // percentage
                __u64         datablocks; // size of data device in fsblocks
                __u64         rtblocks; // size of realtime device in fsblocks
                __u64         rtextents; // number of extents that can be allocated on rtdev
                __u64         logstart; // start of log in fsblocks
                unsigned char uuid[16];
                __u32         sunit; // size of a raid stripe unit of the underlying device in fsblocks
                __u32         swidth; // size of width of a raid stripe on underlying device in raid stripe units
                __s32         version; // version of this structure
                __u32         flags; // enabled features
                __u32         logsectsize; // smallest amount of data can be written to log device atomically in bytes
                __u32         rtsectsize; // smallest amount of data can be written to rtdev atomically in bytes
                __u32         dirblocksize; // size of directory blocks in bytes
                // struct xfs_fsop_geom_v1 stops here.

                __u32         logsunit; // size of raid stripe unit on the underlying log device in fsblocks
                // struct xfs_fsop_geom_v4 stops here.

                __u32         sick;
                __u32         checked;
                __u64         reserved[17];
           };
*/

uint32_t get_agsize(int fd, int ag) {
	struct xfs_ag_geometry geo = { 0 };

	geo.ag_number = ag;

	if (ioctl(fd, XFS_IOC_AG_GEOMETRY, &geo)) {
		output("error calling xfsctl: %m\n");
		exit(EXIT_FAILURE);
	}
	return geo.ag_length; /* in units of filesystem blocks */
}
/*
       int ioctl(int fd, XFS_IOC_AG_GEOMETRY, struct xfs_ag_geometry *arg);

DESCRIPTION
       This  XFS  ioctl retrieves the geometry information for a given allocation group.  The geometry information is conveyed
       in a structure of the following form:

           struct xfs_ag_geometry {
                uint32_t  ag_number;
                uint32_t  ag_length;
                uint32_t  ag_freeblks;
                uint32_t  ag_icount;
                uint32_t  ag_ifree;
                uint32_t  ag_sick;
                uint32_t  ag_checked;
                uint32_t  ag_flags;
                uint64_t  ag_reserved[12];
*/


int get_extents(const char *path, int fd) {
	struct fsxattr fsxattr;

	if (xfsctl(path, fd, FS_IOC_FSGETXATTR, &fsxattr)) {
		output("error calling xfsctl(FS_IOC_FSGETXATTR): %m\n");
		exit(EXIT_FAILURE);
	}
	/* alternately, possibly: ret = ioctl(fd, FS_IOC_FSGETXATTR, &fsxattr); */
	return fsxattr.fsx_nextents;
}
#if 0
 * Structure for FS_IOC_FSGETXATTR[A] and FS_IOC_FSSETXATTR.
struct fsxattr {
        __u32           fsx_xflags;     /* xflags field value (get/set) */
        __u32           fsx_extsize;    /* extsize field value (get/set)*/
        __u32           fsx_nextents;   /* nextents field value (get)   */
        __u32           fsx_projid;     /* project identifier (get/set) */
        __u32           fsx_cowextsize; /* CoW extsize field value (get/set)*/
        unsigned char   fsx_pad[8];
#endif

int get_extents_long(int fd) {
	struct getbmapx all_bmaps[1025];
	struct getbmapx *bmap_hdr = all_bmaps, *bmaps = &all_bmaps[1];
	int extents = 0;
	int e = 0;

	bmap_hdr->bmv_offset = 0;
	bmap_hdr->bmv_length = -1;
	bmap_hdr->bmv_count = 1024;
	bmap_hdr->bmv_iflags = 0;
	while (42) {
		if ((ioctl(fd, XFS_IOC_GETBMAPX, bmap_hdr)) < 0) {
			output("error calling XFS_IOC_GETBMAPX: %m\n");
			return EXIT_FAILURE;
		}
		extents += bmap_hdr->bmv_entries;
		if (bmap_hdr->bmv_entries == 0)
			break;

		int i;
		output("more extents:\n");
		for (i = 0 ; i < bmap_hdr->bmv_entries ; i++) {
			output("extent %d - file offset; %l" PRId64 "; physical starting block: %l" PRId64 "; length of segment: %l" PRId64 "\n",
				e++, bmaps[i].bmv_offset, bmaps[i].bmv_block, bmaps[i].bmv_length);
		}
	}
	return extents;

/*
           struct getbmapx {
                __s64   bmv_offset; // file offset of the segment
                __s64   bmv_block; // physical starting block of segment (if -1, then a hole)
                __s64   bmv_length; // length of segment
                __s32   bmv_count;
                __s32   bmv_entries;
                __s32   bmv_iflags;
                __s32   bmv_oflags;
                __s32   bmv_unused1;
                __s32   bmv_unused2;
           };
       All sizes and offsets in the structure are in units of 512 bytes.

       On successful return from a call, the offset and length values in the header are updated so that  the  command  can  be
       reused to obtain more information.  The remaining elements of the array will be filled out by the call as follows:

       bmv_oflags
*/
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
//		this_inum = get_inum(dfd, run_data.filename);
		this_inum = get_inum(fd, "");
		if (this_inum < run_data.root_inum) {
//			output("found an inode number (%" PRIu64 ") less than root (%" PRIu64 ") for %s/%s\n",
//				this_inum, run_data.root_inum, dir_path, run_data.filename);
			asprintf(&run_data.success_path, "%s/%s", dir_path, run_data.filename);
			run_data.success_inum = this_inum;
		} else if (FILE_BLOCKS) {
			if ((fallocate(fd, 0, 0, FILE_BLOCKS * run_data.fsblock_size)) < 0) {
				output("failed to allocate: %m\n");
				return EXIT_FAILURE;
			}
		}

		close(fd);
		if (run_data.success_path)
			break;
	}
	return EXIT_SUCCESS;
}
int make_subdirs(const char *base_path, int dfd) {
	int subdir_fd, dir_i = 0;
	uint64_t this_inum;
	char *subdir_path = NULL;

	asprintf(&subdir_path, "%s/%s", base_path, run_data.dirname);
	for (dir_i = 0 ; dir_i < MAX_DIRS ; dir_i++) {
		make_dirname(dir_i);
		sprintf(subdir_path, "%s/%s", base_path, run_data.dirname);

		if ((mkdirat(dfd, run_data.dirname, 0755)) < 0) {
			output("error creating subdir: %m\n");
			run_data.dirs_created = dir_i;
			run_data.files_created = 0;
//			return EXIT_FAILURE;
			goto out;
		}
		this_inum = get_inum(dfd, run_data.dirname);
		if (this_inum < run_data.root_inum) {
//			output("found an inode number (%" PRIu64 ") less than root (%" PRIu64 ") for %s/%s\n",
//				this_inum, run_data.root_inum, base_path, run_data.dirname);
			asprintf(&run_data.success_path, "%s/%s", subdir_path, run_data.dirname);
			run_data.success_inum = this_inum;
//			break;
			goto out;
		}
		if ((subdir_fd = openat(dfd, run_data.dirname, O_RDONLY|O_DIRECTORY)) < 0) {
			output("error opening subdirectory: %m\n");
			run_data.dirs_created = dir_i + 1;
			run_data.files_created = 0;
			goto out;
		}


		if (dir_i == 0 || __builtin_popcount(dir_i) == 1)
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
	mkdirat(AT_FDCWD, mountpoint, 0755);
	if ((sudo_umount(mountpoint, true)) < 0) {
		output("couldn't unmount: %m\n");
		exit(EXIT_FAILURE);
	}
}
void make_img(const char *image) {
	int img_fd;

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
	sudo_chown(mountpoint, run_data.uid, run_data.gid);
}

/* returns a size in bytes */
uint64_t parse_size(const char *size_str) {
	uint64_t size = 0;
	int shift = 0;
	char *p;

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
		size = size * (1ULL << (shift * 10));
out:
	return size;

out_badsize:
	output("unrecognized size: '%s'\n", p);
	return 0;
}

void add_filler(int dfd) {
	uint64_t min_blocks = (run_data.agblocks) - 1024UL;

	uint64_t base_alloc_blocks = min_blocks - 10000;
	if (base_alloc_blocks < 0)
		base_alloc_blocks = 0;
	uint64_t add_blocks = 0;

	int fill_fd;
	if ((fill_fd = openat(dfd, "filler", O_CREAT|O_RDWR|O_TRUNC, 0644)) < 0) {
		output("error opening filler file: %m\n");
		exit(EXIT_FAILURE);
	}
	output("starting search with %" PRIu64 " blocks\n", base_alloc_blocks + add_blocks);
	while (42) {
		uint64_t alloc_blocks = base_alloc_blocks + add_blocks;
		uint64_t extents;

		ftruncate(fill_fd, 0);
		if ((fallocate(fill_fd, 0, 0, alloc_blocks * run_data.fsblock_size)) < 0) {
			output("failed to allocate: %m\n");
			exit(EXIT_FAILURE);
		}
		extents = get_extents("mnt/filler", fill_fd);

		if (extents > 1) {
			output("allocated size: %" PRIu64", number of extents for filler file: %" PRIu64 "\n",
				alloc_blocks, extents);
			break;
		}
		add_blocks += 8;
	}
	output("ended search with %" PRIu64 " blocks (base + %" PRIu64 ")\n", base_alloc_blocks + add_blocks, add_blocks);

	get_extents_long(fill_fd);

	close(fill_fd);
}


int main(int argc, char *argv[]) {
	char *mountpoint = "mnt";
	char *image = "fsfile.img";
	int root_dfd;

	if (argc == 2) {
		run_data.image_size = parse_size(argv[1]);
		if (run_data.image_size == 0)
			return EXIT_FAILURE;
	} else
		run_data.image_size = IMAGE_SIZE;

	if (run_data.image_size < 16777216) {
		output("image size is too small.  must be at least 16 MiB (16777216)\n");
		return EXIT_FAILURE;
	}

	run_data.uid = getuid();
	run_data.gid = getgid();
	if (run_data.uid != 0 || run_data.gid != 0) {
		asprintf(&run_data.uid_gid, "%d:%d", run_data.uid, run_data.gid);
	}

	output("cleaning up from any prior runs...\n");
	cleanup(mountpoint);

	output("creating image...\n");
	make_img(image);
	mount_image(image, mountpoint);

	if ((root_dfd = openat(AT_FDCWD, mountpoint, O_RDONLY|O_DIRECTORY)) < 0) {
		output("error opening directory for mountpoint: %m\n");
		return EXIT_FAILURE;
	}

	get_fsgeo(root_dfd);
	output("agcount: %d\n", run_data.agcount);
	output("agblocks: %d\n", run_data.agblocks);
	output("datablocks: %" PRIu64 "\n", run_data.datablocks);
	output("inode size: %d\n", run_data.ino_size);
	if (0) {
		int i;
		for (i = 0 ; i < run_data.agcount ; i++) {
			uint32_t agsize = get_agsize(root_dfd, i);
			printf("  ag %d - %d fsblocks\n", i, agsize);
		}
	}

	run_data.root_inum = get_inum(root_dfd, "");
	output("root inode: %" PRIu64 "\n", run_data.root_inum);

	make_dirname(MAX_DIRS);
	make_filename(MAX_IN_DIR);

	if (ADD_FILLER) {
		add_filler(root_dfd);
	} /* ADD_FILLER */


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
