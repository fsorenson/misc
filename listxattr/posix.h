/*
	Frank Sorenson <sorenson@redhat.com>, 2022


	Display xattrs attached to a file/directory,
	and decode as many of them as possible
*/

#ifndef __LISTXATTR_POSIX_H__
#define __LISTXATTR_POSIX_H__

#include "listxattr.h"

static const char *perm_str[] = { "---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx" };

void *show_posix_acl(const char *attr_name, const unsigned char *buf, int len, bool is_dir);

#endif /* __LISTXATTR_POSIX_H__ */
