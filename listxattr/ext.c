/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible

	gcc listxattr.c -o listxattr -lacl
*/

#include <stdio.h>
/*
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <attr/xattr.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <acl/libacl.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <linux/fs.h>
#include <sys/vfs.h>
*/

#include "ext.h"

void decode_ioctl_flags_ext(unsigned long val) {
	check_flag(val, EXT4_SYNC_FL);
	check_flag(val, EXT4_IMMUTABLE_FL);
	check_flag(val, EXT4_APPEND_FL);
	check_flag(val, EXT4_NODUMP_FL);
	check_flag(val, EXT4_NOATIME_FL);
	check_flag(val, EXT4_DIRTY_FL);
	check_flag(val, EXT4_COMPRBLK_FL);
	check_flag(val, EXT4_NOCOMPR_FL);
	check_flag(val, EXT4_ECOMPR_FL);
	check_flag(val, EXT4_INDEX_FL);
	check_flag(val, EXT4_IMAGIC_FL);
	check_flag(val, EXT4_JOURNAL_DATA_FL);
	check_flag(val, EXT4_NOTAIL_FL);
	check_flag(val, EXT4_DIRSYNC_FL);
	check_flag(val, EXT4_TOPDIR_FL);
	check_flag(val, EXT4_HUGE_FILE_FL);
	check_flag(val, EXT4_EXTENTS_FL);
	check_flag(val, EXT4_EA_INODE_FL);
	check_flag(val, EXT4_EOFBLOCKS_FL);
	check_flag(val, EXT4_INLINE_DATA_FL);
	check_flag(val, EXT4_RESERVED_FL);

}

