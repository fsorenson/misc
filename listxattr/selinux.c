/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible

	gcc listxattr.c -o listxattr -lacl
*/

#include "selinux.h"

void *show_selinux(const char *xattr_name, const unsigned char *xattr, int attr_len, bool is_dir) {
//	show_selinux(attr, attr_len);
	printf("\t%s\n", xattr);

	return NULL;
}
