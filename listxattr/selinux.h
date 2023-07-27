/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible

	gcc listxattr.c -o listxattr -lacl
*/

#ifndef __SELINUX_H__
#define __SELINUX_H__

#include "listxattr.h"
#include "ntacl.h"

void *show_selinux(const char *xattr_name, const unsigned char *attr, int attr_len, bool is_dir);

#endif
