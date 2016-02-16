/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible

	gcc listxattr.c -o listxattr -lacl
*/

#ifndef __EXT_H__
#define __EXT_H__

#include "listxattr.h"

/* flags from fs/ext4/ext4.h */
#define EXT4_SECRM_FL                   0x00000001 /* Secure deletion */
#define EXT4_UNRM_FL                    0x00000002 /* Undelete */
#define EXT4_COMPR_FL                   0x00000004 /* Compress file */
#define EXT4_SYNC_FL                    0x00000008 /* Synchronous updates */
#define EXT4_IMMUTABLE_FL               0x00000010 /* Immutable file */
#define EXT4_APPEND_FL                  0x00000020 /* writes to file may only append */
#define EXT4_NODUMP_FL                  0x00000040 /* do not dump file */
#define EXT4_NOATIME_FL                 0x00000080 /* do not update atime */
/* Reserved for compression usage... */
#define EXT4_DIRTY_FL                   0x00000100
#define EXT4_COMPRBLK_FL                0x00000200 /* One or more compressed clusters */
#define EXT4_NOCOMPR_FL                 0x00000400 /* Don't compress */
#define EXT4_ECOMPR_FL                  0x00000800 /* Compression error */
/* End compression flags --- maybe not all used */
#define EXT4_INDEX_FL                   0x00001000 /* hash-indexed directory */
#define EXT4_IMAGIC_FL                  0x00002000 /* AFS directory */
#define EXT4_JOURNAL_DATA_FL            0x00004000 /* file data should be journaled */
#define EXT4_NOTAIL_FL                  0x00008000 /* file tail should not be merged */
#define EXT4_DIRSYNC_FL                 0x00010000 /* dirsync behaviour (directories only) */
#define EXT4_TOPDIR_FL                  0x00020000 /* Top of directory hierarchies*/
#define EXT4_HUGE_FILE_FL               0x00040000 /* Set to each huge file */
#define EXT4_EXTENTS_FL                 0x00080000 /* Inode uses extents */
#define EXT4_EA_INODE_FL                0x00200000 /* Inode used for large EA */
#define EXT4_EOFBLOCKS_FL               0x00400000 /* Blocks allocated beyond EOF */
#define EXT4_INLINE_DATA_FL             0x10000000 /* Inode has inline data. */
#define EXT4_RESERVED_FL                0x80000000 /* reserved for ext4 lib */

#define EXT4_FL_USER_VISIBLE            0x004BDFFF /* User visible flags */
#define EXT4_FL_USER_MODIFIABLE         0x004380FF /* User modifiable flags */

void decode_ioctl_flags_ext(unsigned long val);

#endif /* __EXT_H__ */
