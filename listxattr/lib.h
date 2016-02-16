/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible
*/

#ifndef __LIB_H__
#define __LIB_H__

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

struct val_char_pair {
	uint64_t val;
	char c;
	char *str;
};

int decode_flags(struct val_char_pair *flag_chars, ulong flags, char *buf);
int decode_type(struct val_char_pair *types, ulong val, char *buf);
void hexprint(char *bytes, int len);

#define check_flag(val,fl) do { \
	if (val & fl) \
		printf("\t%s\n", #fl); \
} while (0)


#endif /* __LIB_H__ */

