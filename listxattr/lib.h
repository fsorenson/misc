/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible
*/

#ifndef __LISTXATTR_LIB_H__
#define __LISTXATTR_LIB_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
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
#include <inttypes.h>
#include <endian.h>

struct val_str_pair {
        long val;
        const char *str;
};

struct val_char_pair {
	uint64_t val;
	char c;
	char *str;
};

int decode_flags(struct val_char_pair *flag_chars, ulong flags, char *buf);
int decode_type(struct val_char_pair *types, ulong val, char *buf);
void hexprint(const unsigned char *bytes, int len);
void hexprint_pad(const char *pad, const unsigned char *buf, int len);
bool printable(const unsigned char *buf, int len);

unsigned char *dehexlify_string(char *string);

char *base64ify(const unsigned char *in, size_t len);
int debase64_len(const char *str);
unsigned char *debase64ify(char *str);


#define check_flag(val,fl) do { \
	if (val & fl) \
		printf("\t%s\n", #fl); \
} while (0)

#ifndef min
#define min(x, y) ({ typeof(x) _x = x; typeof(x) _y = y; _x < _y ? _x : _y; })
#endif
#ifndef max
#define max(x, y) ({ typeof(x) _x = x; typeof(x) _y = y; _x > _y ? _x : _y; })
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif


#endif /* __LISTXATTR_LIB_H__ */

