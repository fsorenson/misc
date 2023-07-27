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

#include "nfs4.h"

static struct val_char_pair nfs4_ace_flag_pairs[] = {
	{ 0x00000001, 'f', "FILE_INHERIT_ACE" },
	{ 0x00000002, 'd', "DIRECTORY_INHERIT_ACE" },
	{ 0x00000004, 'n', "NO_PROPAGATE_INHERIT_ACE" },
	{ 0x00000008, 'i', "INHERIT_ONLY_ACE" },
	{ 0x00000010, 'S', "SUCCESSFUL_ACCESS_ACE_FLAG" },
	{ 0x00000020, 'F', "FAILED_ACCESS_ACE_FLAG" },
	{ 0x00000040, 'g', "IDENTIFIER_GROUP" },
	{ 0x00000080, 'O', "OWNER_AT" },
	{ 0x00000100, 'G', "GROUP_AT" },
	{ 0x00000200, 'E', "EVERYONE_AT" },
	{ 0, 0, 0 }
};

static struct val_char_pair nfs4_ace_perm_dir_pairs[] = {
	{ 0x00000001, 'r', "LIST_DIRECTORY" },
	{ 0x00000002, 'w', "CREATE_FILE" },
	{ 0x00000004, 'a', "CREATE_SUBDIR" },
	{ 0x00000040, 'D', "DELETE_CHILD" },
	{ 0, 0, 0 }
};

static struct val_char_pair nfs4_ace_perm_file_pairs[] = {
	{ 0x00000001, 'r', "READ_DATA" },
	{ 0x00000002, 'w', "WRITE_DATA" },
	{ 0x00000004, 'a', "APPEND_DATA" },
	{ 0, 0, 0 }
};

static struct val_char_pair nfs4_ace_perm_common_pairs[] = {
	{ 0x00010000, 'd', "DELETE" },
	{ 0x00000020, 'x', "EXECUTE" },
	{ 0x00000080, 't', "READ_ATTRIBUTES" },
	{ 0x00000100, 'T', "WRITE_ATTRIBUTES" },
	{ 0x00000008, 'n', "READ_NAMED_ATTR" },
	{ 0x00000010, 'N', "WRITE_NAMED_ATTR" },
	{ 0x00020000, 'c', "READ_ACL" },
	{ 0x00040000, 'C', "WRITE_ACL" },
	{ 0x00080000, 'o', "WRITE_OWNER" },
	{ 0x00100000, 'y', "SYNCHRONIZE" },
	{ 0, 0, 0 }
};

static struct val_char_pair nfs4_ace_type_pairs[] = {
	{ 0, 'A', "ALLOW" },
	{ 1, 'D', "DENY" },
	{ 2, 'U', "AUDIT" },
	{ 3, 'L', "ALARM" },
	{ 0, 0, 0 }
};

/* from nfs4-acl_tools */
#define NFS4_MAX_PRINCIPALSIZE  (128 + 256 + 1 + 1)

#pragma pack(1)
struct nfs4_ace_struct {
	uint32_t ace_type;
	uint32_t flag;
	uint32_t access_mask;
	uint32_t who_len;
	char *who;
};
#pragma pack()

#pragma pack(1)
struct nfs4_acl_struct {
	uint32_t num_aces;
	struct nfs4_ace_struct *aces;
};
#pragma pack()


int nfs4_get_ace_flags2(struct nfs4_ace_struct *ace, char *buf) {
	int flags = ace->flag;
	char *bp = buf;
	int len;

	len = decode_flags(nfs4_ace_flag_pairs, flags, buf);
	buf += len;
	*buf++ = ':';
	*buf = '\0';

	return (buf - bp);
}

int nfs4_get_ace_type(struct nfs4_ace_struct *ace, char *buf) {
	char *bp = buf;
	int len;

	len = decode_type(nfs4_ace_type_pairs, ace->ace_type, buf);
	buf += len;
	*buf++ = ':';
	*buf = '\0';
	return (buf - bp);
}

char *nfs4_get_ace_access(struct nfs4_ace_struct *ace, char *buf, int is_dir) {
	int mask = ace->access_mask;
	char *bp = buf;
	int len;

	if (is_dir)
		len = decode_flags(nfs4_ace_perm_dir_pairs, mask, buf);
	 else
		len = decode_flags(nfs4_ace_perm_file_pairs, mask, buf);
	buf += len;

	len = decode_flags(nfs4_ace_perm_common_pairs, mask, buf);
	buf += len;
	*buf = '\0';

	return bp;
}

int nfs4_print_ace(struct nfs4_ace_struct *ace, uint32_t is_dir) {
	char buf[16];
	int offset = 0;

	if (!(offset = nfs4_get_ace_type(ace, buf))) {
		printf("Unknown ACE type: %d\n", ace->ace_type);
		goto failed;
	}
	offset += nfs4_get_ace_flags2(ace, buf + offset);

	printf("\t%s", buf);

	printf("%s:", ace->who);
	printf("%s\n", nfs4_get_ace_access(ace, buf, is_dir));

	return 0;
failed:
	printf("Error printing ACE.\n");
	return 1;
}

void nfs4_print_acl(struct nfs4_acl_struct *acl, int is_dir) {
	struct nfs4_ace_struct *ace;
	int i;

	for (i = 0 ; i < acl->num_aces ; i ++) {
		ace = &acl->aces[i];
		nfs4_print_ace(ace, is_dir);
	}
}


void *show_nfs4_acl(const char *attr_name, const unsigned char *buf, int len, bool is_dir) {
	struct nfs4_acl_struct acl;
	int ace_i;

	acl.num_aces = (uint32_t)ntohl(*((uint32_t *)buf));
	buf += sizeof(uint32_t);
	len -= sizeof(uint32_t);

	if (len <= 0) {
		errno = EINVAL;
		goto err1;
	}
	acl.aces = malloc(sizeof(struct nfs4_ace_struct) * acl.num_aces);
	for (ace_i = 0 ; ace_i < acl.num_aces ; ace_i ++) {
		memcpy(&acl.aces[ace_i], buf, sizeof(struct nfs4_ace_struct) - sizeof(char *));
		acl.aces[ace_i].ace_type = ntohl(acl.aces[ace_i].ace_type);
		acl.aces[ace_i].flag = ntohl(acl.aces[ace_i].flag);
		acl.aces[ace_i].access_mask = ntohl(acl.aces[ace_i].access_mask);
		acl.aces[ace_i].who_len = ntohl(acl.aces[ace_i].who_len);

		buf += sizeof(struct nfs4_ace_struct) - sizeof(char *);
		len -= (sizeof(struct nfs4_ace_struct) - sizeof(char *));

		acl.aces[ace_i].who = malloc((acl.aces[ace_i].who_len + 1) * sizeof(char));

		memcpy(acl.aces[ace_i].who, buf, acl.aces[ace_i].who_len);
		acl.aces[ace_i].who[acl.aces[ace_i].who_len] = '\0';

		int skip = ((acl.aces[ace_i].who_len + (sizeof(uint32_t) -1)) / sizeof(uint32_t)) * sizeof(uint32_t);

		buf += skip;
		len -= skip;
		if (len < 0)
			goto err2;
	}
	nfs4_print_acl(&acl, is_dir);
	return 0;

err2:
#if DEBUG
	printf("skipping to err2, len = %d\n", len);
#endif /* DEBUG */
	free(acl.aces[ace_i].who);
err1:
#if DEBUG
	printf("skipping to err1\n");
#endif /* DEBUG */
	free(acl.aces);
	return NULL;
}

