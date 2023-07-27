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

#include "xfs.h"
#include <sys/acl.h>


#if 0
struct xfs_acl_entry {
        __be32  ae_tag;
        __be32  ae_id;
        __be16  ae_perm;
        __be16  ae_pad;         /* fill the implicit hole in the structure */
};

struct xfs_acl {
        __be32                  acl_cnt;
        struct xfs_acl_entry    acl_entry[];
};
#endif

#include "posix.h"

void *show_xfs_acl(const char *name, const unsigned char *buf, int len, bool is_dir) {
	struct xfs_acl *xfs_acl = (struct xfs_acl *)buf;
	struct xfs_acl_entry *ace;
	int i;

//	printf("acl count: %d\n", htobe32(xfs_acl->acl_cnt));
	xfs_acl->acl_cnt = htobe32(xfs_acl->acl_cnt);
//	printf("acl count: 0x%08x\n", htobe32(xfs_acl->acl_cnt));
	printf("acl count: %d\n", xfs_acl->acl_cnt);


//	struct posix_acl *acl = posix_acl_alloc(xfs_acl->acl_cnt);
//	acl_t *acl = posix_acl_alloc(xfs_acl->acl_cnt);


	for (i = 0 ; i < xfs_acl->acl_cnt ; i++) {
//		struct posix_acl_entry *acl_e = &acl->a_entries[i];
//		acl_entry_t *acl_e = &acl->a_entries[i];
		ace = &xfs_acl->acl_entry[i];

		ace->ae_tag = htobe32(ace->ae_tag);
		ace->ae_id = htobe32(ace->ae_id);
		ace->ae_perm = htobe32(ace->ae_perm);

		switch (ace->ae_tag) {
			case ACL_USER:
//				printf("user:%d:%s\n", acl_e->e_uid, perm_str[acl_e->e_perm]);
				printf("user:%d:%s\n", ace->ae_id, perm_str[ace->ae_perm]);
				break;
			case ACL_GROUP:
//				acl_e->e_gid = htobe32(ace->ae_id);
				printf("group:%d:%s\n", ace->ae_id, perm_str[ace->ae_perm]);
				break;
			case ACL_USER_OBJ:
				printf("user:(OWNER):%s\n", perm_str[ace->ae_perm]);
				break;
			case ACL_GROUP_OBJ:
				printf("user:(GROUP):%s\n", perm_str[ace->ae_perm]);
				break;
			case ACL_MASK:
				printf("mask::%s\n", perm_str[ace->ae_perm]);
				break;
			case ACL_OTHER:
				printf("other:%d:%s\n", ace->ae_id, perm_str[ace->ae_perm]);
				break;
			default:
printf("tag: %d\n", ace->ae_tag);
				goto out;
				break;
		}
	}



out:
	return NULL;
}
