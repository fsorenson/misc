/*
	Frank Sorenson <sorenson@redhat.com>, 2022


	Display xattrs attached to a file/directory,
	and decode as many of them as possible
*/

#ifndef __LISTXATTR_CAPABILITY_H__
#define __LISTXATTR_CAPABILITY_H__

#include "../listxattr.h"
#include "../encdec.h"

#include <linux/capability.h>

void *decode_capability(const char *attr_name, const unsigned char *buf, int len, bool is_dir);

#endif /* __LISTXATTR_CAPABILITY_H__ */
