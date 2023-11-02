#ifndef __CIRCLEFS_H__
#define __CIRCLEFS_H__
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <math.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>

struct circlefs_data {
	long double radius;
	struct timespec mount_time;
	struct timespec modify_time;
	struct timespec access_time;
	uid_t uid;
	gid_t gid;
};
extern struct circlefs_data circlefs_data;

struct circlefs_dirent {
	char *name;     // entry name
	struct stat st; // permissions, inode number, etc.
};
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#define BLOCK_SIZE      42
#define FILE_SIZE       4096
#define DEVICE_MAJOR    42
#define DEVICE_MINOR    42

#define NUM_BLOCKS(size, bsize) ( (size + bsize - 1) / bsize )

// helper function to fill a directory entry's 'struct stat'
static void fill_statbuf(struct circlefs_dirent *ent) {
	ent->st.st_uid = circlefs_data.uid;
	ent->st.st_gid = circlefs_data.gid;
	ent->st.st_size = FILE_SIZE;
	ent->st.st_blksize = BLOCK_SIZE;
	ent->st.st_blocks = NUM_BLOCKS(FILE_SIZE, BLOCK_SIZE),
	ent->st.st_dev = makedev(DEVICE_MAJOR, DEVICE_MINOR);
	ent->st.st_ctim = circlefs_data.mount_time;
	ent->st.st_mtim = (!strcmp(ent->name, "pi")) ? circlefs_data.mount_time :
		circlefs_data.modify_time;
	ent->st.st_atim = circlefs_data.access_time;
}

#endif
