/*
	Frank Sorenson <sorenson@redhat.com>, 2022


	Display xattrs attached to a file/directory,
	and decode as many of them as possible
*/

#ifndef __LISTXATTR_XFS_H__
#define __LISTXATTR_XFS_H__

#include <xfs/xfs.h>
#include <xfs/xfs_format.h>
#include "listxattr.h"
#include "encdec.h"

int decode_xfs_acl(const char *name, const unsigned char *buf, int len, bool is_dir);

#endif /* __LISTXATTR_XFS_H__ */
