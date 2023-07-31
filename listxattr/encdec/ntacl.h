/*
	Frank Sorenson <sorenson@redhat.com>, 2022

	Display xattrs attached to a file/directory,
	and decode as many of them as possible
*/

#ifndef __LISTXATTR_NTACL_H__
#define __LISTXATTR_NTACL_H__

#include "listxattr.h"
#include "encdec.h"

#define ACL_SMBCACLS "security.NTACL"

int decode_NTACL(const char *name, const unsigned char *buf, int len, bool is_dir);

#endif /* __LISTXATTR_NTACL_H__ */
