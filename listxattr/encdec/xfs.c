/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible
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

int decode_xfs_acl(const char *name, const unsigned char *buf, int len, bool is_dir) {
	struct xfs_acl *xfs_acl = (struct xfs_acl *)buf;
	struct xfs_acl_entry *ace;
	int ret = EXIT_SUCCESS, i;

	xfs_acl->acl_cnt = htobe32(xfs_acl->acl_cnt);
	printf("acl count: %d\n", xfs_acl->acl_cnt);

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
	return ret;
}

static char *xfs_xattrs[] = {
	"trusted." SGI_ACL_FILE,
	"trusted." SGI_ACL_DEFAULT,
	NULL,
};

static struct encdec_ops_struct encdec_xfs_ops = {
	.init = NULL,
	.decode = decode_xfs_acl,
	.cleanup = NULL,
};

ADD_ENCDEC(xfs, "xfs acls", &encdec_xfs_ops, xfs_xattrs);
