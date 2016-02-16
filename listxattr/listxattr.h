/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible

	gcc listxattr.c -o listxattr -lacl
*/

#ifndef __LISTXATTR_H__
#define __LISTXATTR_H__
/*
#include <stdio.h>
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
#include "lib.h"

#define ACL_NFS4_XATTR          "system.nfs4_acl"
#define ACL_SELINUX_XATTR       "security.selinux"
#define ACL_POSIX_ACCESS        "system.posix_acl_access"
#define ACL_POSIX_DEFAULT       "system.posix_acl_default"

/* lots of xattrs defined in include/uapi/linux/xattr.h */

#endif /* __LISTXATTR_H__ */
