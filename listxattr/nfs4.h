/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible
*/

#ifndef __NFS4_H__
#define __NFS4_H__

#include "listxattr.h"

void *show_nfs4_acl(char *buf, int len, int is_dir);

#endif /* __NFS4_H__ */
