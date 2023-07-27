/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible
*/

/*
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
*/

#include "posix.h"
#include <sys/acl.h>


#if 0

/*=== Data types ===*/

struct __acl_ext;
struct __acl_entry_ext;
struct __acl_permset_ext;

typedef unsigned int            acl_type_t;
typedef int                     acl_tag_t;
typedef unsigned int            acl_perm_t;

typedef struct __acl_ext        *acl_t;
typedef struct __acl_entry_ext  *acl_entry_t;
typedef struct __acl_permset_ext *acl_permset_t;
#endif

struct ace {

	uint16_t tag;
	uint16_t perm;
	uint32_t id;
};

/*
typedef unsigned int            acl_type_t;
typedef int                     acl_tag_t;
typedef unsigned int            acl_perm_t;

typedef struct __acl_ext        *acl_t;
typedef struct __acl_entry_ext  *acl_entry_t;
typedef struct __acl_permset_ext *acl_permset_t;
*/

#if 0
/*=== Constants ===*/

/* 23.2.2 acl_perm_t values */

#define ACL_READ                (0x04)
#define ACL_WRITE               (0x02)
#define ACL_EXECUTE             (0x01)

/* 23.2.5 acl_tag_t values */

#define ACL_UNDEFINED_TAG       (0x00)
#define ACL_USER_OBJ            (0x01)
#define ACL_USER                (0x02)
#define ACL_GROUP_OBJ           (0x04)
#define ACL_GROUP               (0x08)
#define ACL_MASK                (0x10)
#define ACL_OTHER               (0x20)

/* 23.3.6 acl_type_t values */

#define ACL_TYPE_ACCESS         (0x8000)
#define ACL_TYPE_DEFAULT        (0x4000)

/* 23.2.7 ACL qualifier constants */

#define ACL_UNDEFINED_ID        ((id_t)-1)

/* 23.2.8 ACL Entry Constants */

#define ACL_FIRST_ENTRY         0
#define ACL_NEXT_ENTRY          1
#endif


#if 0
#define ACL_UNDEFINED_TAG       (0x00)
#define ACL_USER_OBJ            (0x01)
#define ACL_USER                (0x02)
#define ACL_GROUP_OBJ           (0x04)
#define ACL_GROUP               (0x08)
#define ACL_MASK                (0x10)
#define ACL_OTHER               (0x20)
#endif
const char *posix_tag_name(int tag) {
	switch (tag) {
		case ACL_UNDEFINED_TAG: return "UNDEFINED"; break;
		case ACL_USER_OBJ: return "USER_OBJ"; break;
		case ACL_USER: return "USER"; break;
		case ACL_GROUP_OBJ: return "GROUP_OBJ"; break;
		case ACL_GROUP: return "GROUP"; break;
		case ACL_MASK: return "MASK"; break;
		case ACL_OTHER: return "OTHER"; break;
		default: return "ERROR"; break;
	}
}
//static const char *perm_str[] = { "---", "--x", "-w-", "-wx", "r--", "--x", "rw-", "rwx" };
//static const char *perm_str[] = { "---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx" };

void *show_posix_acl(const char *attr_name, const unsigned char *buf, int len, bool is_dir) {
	unsigned char *p = (unsigned char *)buf;
	bool is_default = false;

	int entry_count = (len - 4) / sizeof(struct ace);

	if (!strcmp(attr_name, ACL_POSIX_DEFAULT))
		is_default = true;
	printf("posix acl... version: %d; %d ACEs\n", *(uint32_t *)p, entry_count);

	p += 4;
	while (p < buf + len) {
		struct ace *ace = (struct ace *)p;

		switch (ace->tag) {
			case ACL_UNDEFINED_TAG:
				printf("%sUNDEFINED:%d:%s\n",
					is_default ? "default:" : "",
					ace->id, perm_str[ace->perm]);
				break;
			case ACL_USER_OBJ:
				printf("%suser:(owner):%s\n",
					is_default ? "default:" : "",
					perm_str[ace->perm]);
				break;
			case ACL_USER:
				printf("%suser:%d:%s\n",
					is_default ? "default:" : "",
					ace->id, perm_str[ace->perm]);
				break;
			case ACL_GROUP_OBJ:
				printf("%sgroup:(owner_group):%s\n",
					is_default ? "default:" : "",
					perm_str[ace->perm]);
				break;
			case ACL_GROUP:
				printf("%sgroup:%d:%s\n",
					is_default ? "default:" : "",
					ace->id, perm_str[ace->perm]);
				break;
			case ACL_MASK:
				printf("%smask::%s\n",
					is_default ? "default:" : "",
					perm_str[ace->perm]);
				break;
			case ACL_OTHER:
				printf("%sother::%s\n",
					is_default ? "default:" : "",
					perm_str[ace->perm]);
				break;
			default: return "ERROR"; break;
		};

		p += sizeof(struct ace);
	}
	return NULL;
}
