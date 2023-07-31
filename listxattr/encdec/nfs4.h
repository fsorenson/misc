/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible
*/

#ifndef __LISTXATTR_NFS4_H__
#define __LISTXATTR_NFS4_H__

#include "listxattr.h"

#define ACL_NFS4_XATTR	"system.nfs4_acl"
#define DACL_NFS4_XATTR	"system.nfs4_dacl"
#define SACL_NFS4_XATTR	"system.nfs4_sacl"

int decode_nfs4_acl(const char *attr_name, const unsigned char *buf, int len, bool is_dir);

#endif /* __LISTXATTR_NFS4_H__ */
