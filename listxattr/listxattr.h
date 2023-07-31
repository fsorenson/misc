/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible

	gcc listxattr.c -o listxattr -lacl
*/

#ifndef __LISTXATTR_H__
#define __LISTXATTR_H__

#include "lib.h"
#include <linux/xattr.h>

#define ACL_NFS4_XATTR		"system.nfs4_acl"
#define DACL_NFS4_XATTR		"system.nfs4_dacl"
#define SACL_NFS4_XATTR		"system.nfs4_sacl"
#define ACL_SELINUX_XATTR	"security.selinux"
#define CAPABILITY_XATTR	"security.capability"
#define ACL_POSIX_ACCESS	"system.posix_acl_access"
#define ACL_POSIX_DEFAULT	"system.posix_acl_default"

#define ACL_SMBCACLS		"security.NTACL"

#define free_mem(ptr) do { if (ptr) free(ptr); ptr = NULL; } while (0)

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define exit_fail(args...) do { \
	output(args); \
	exit(-1); \
} while (0)

typedef int (show_acl_t)(const char *attr_name, const unsigned char *attr_bytes, int len, bool is_dir);

/* lots of xattrs defined in include/uapi/linux/xattr.h */

#endif /* __LISTXATTR_H__ */
