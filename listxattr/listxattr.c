/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible

	gcc listxattr.c -o listxattr -lacl
*/

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

#define DEBUG 0

#define DEBUG 0





#define P_ACL_TYPE_DEFAULT	(0x4000)
#define P_ACL_TYPE_ACCESS	(0x8000)

/* e_tag entry in acl_entry */
#define P_ACL_USER_OBJ	(0x01)
#define P_ACL_USER	(0x02)
#define P_ACL_GROUP_OBJ	(0x04)
#define P_ACL_GROUP	(0x08)
#define P_ACL_MASK	(0x10)
#define P_ACL_OTHER	(0x20)

/* e_perm field */
#define P_ACL_EXECUTE	(0x01)
#define P_ACL_WRITE	(0x02)
#define P_ACL_READ	(0x04)
struct p_acl_entry {
	short		e_tag;
	unsigned short	e_perm;
	union {
		uid_t	e_uid;
		gid_t	e_gid;
	};
};
struct p_acl {
	int	a_refcount;
	unsigned int	a_count;
	struct p_acl_entry	a_entries[0];
};
#define foreach_p_acl_entry(pa, acl, pe) \
	for (pa = (typeof(pa))((acl)->a_entries), pe = (typeof (pe))(pa + (acl)->a_count) ; (void *)pa < (void *)pe ; pa ++)


void parse_posix_acl(char *acl_buf, int len) {
	struct p_acl_entry *p_entry, *pe;
	struct p_acl *p_acl, *pa;

	p_acl = (struct p_acl *)acl_buf;


	printf("acl entries: %d\n", p_acl->a_count);

	foreach_p_acl_entry(pa, p_acl, pe) {
		printf("parsing an acl entry\n");
	}

}


void show_acl(const char *path, acl_type_t type) {
#if DEBUG
	printf("size of 'acl_t' = %ld\n", sizeof(acl_t));
#endif /* DEBUG */
	acl_t acl = acl_get_file(path, type);

	if (acl == NULL) {
		printf("Unable to get %s acl for %s: %m\n",
			type == ACL_TYPE_DEFAULT ? "default" : "access",
			path);
	} else {
		char *acl_text;
//		ssize_t acl_len;
#if DEBUG
	int s = acl_size(acl);
	printf("size of this acl: %d\n", s);
	printf("contents of this acl:  ");
	hexprint((char *)acl, s);
#endif /* DEBUG */

//		acl_text = acl_to_text(acl, &acl_len);
		acl_text = acl_to_any_text(acl, "\n\t", ':', TEXT_ALL_EFFECTIVE);
		if (acl_text != NULL) {
			printf("%s acl is %s\n",
				type == ACL_TYPE_DEFAULT ? "default" : "access",
				acl_text);
			acl_free(acl_text);
		}
		acl_free(acl);
	}
}


void do_acl_checks(char *path) {
	int ret;
	acl_t acl;
//	acl_entry_t acl_entry;

	/* check for 'extended access ACL */
	ret = acl_extended_file(path);
	if (ret == 1) {
		printf("%s has an extended access ACL or a default ACL\n", path);
	} else if (ret == 0) {
//		printf("%s does not have either an extended access ACL or a default ACL\n", path);
		return;
	} else if (ret == -1) {
		printf("an error occurred while checking for extended access ACL/default ACL for %s: %m\n", path);
		return;
	}

	acl = acl_get_file(path, ACL_TYPE_DEFAULT);
	if (acl == NULL) {
		printf("Unable to get default acl for %s: %m\n", path);
	} else {
		char *acl_text;
		ssize_t acl_len;

		acl_text = acl_to_text(acl, &acl_len);
		if (acl_text != NULL) {
			printf("default acl is %s\n", acl_text);
			acl_free(acl_text);
		}
//parse_posix_acl((char *)acl, acl_len);

		acl_free(acl);
	}

	acl = acl_get_file(path, ACL_TYPE_ACCESS);
	if (acl == NULL) {
		printf("Unable to get access acl for %s: %m\n", path);
	} else {
		char *acl_text;
		ssize_t acl_len;

		acl_text = acl_to_text(acl, &acl_len);
		if (acl_text != NULL) {
			printf("access acl is %s\n", acl_text);
			acl_free(acl_text);
		}
//parse_posix_acl((char *)acl, acl_len);
		acl_free(acl);
	}

//		ret = acl_get_entry(acl, ACL_FIRST_ENTRY, &acl_entry);
//		if (ret == 1) {
//			char *acl_text;
//
//			acl_text = acl_to_text(

//ACL_TYPE_ACCESS

}


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

#define ACL_NFS4_XATTR		"system.nfs4_acl"
#define ACL_SELINUX_XATTR	"security.selinux"
#define ACL_POSIX_ACCESS	"system.posix_acl_access"
#define ACL_POSIX_DEFAULT	"system.posix_acl_default"


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


void *show_nfs4_acl(char *buf, int len, int is_dir) {
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

void show_selinux(char *attr, int attr_len) {
//	show_selinux(attr, attr_len);
	printf("\t%s\n", attr);
}

int main(int argc, char *argv[]) {
	char *attr_list;
	char *attr;
	int list_len, ret;
	int attr_buf_len = 512;
	int attr_len;
	char *path = argv[1];
	int is_dir = 0;
	struct stat st;

	ret = stat(path, &st);
	if (ret < 0) {
		printf("Bad path: %s\n", path);
		return -1;
	}
	if (st.st_mode & S_IFDIR)
		is_dir = 1;


	attr = malloc(attr_buf_len);

//	do_acl_checks(path);

	list_len = listxattr(path, NULL, 0);
#if DEBUG
	printf("got %d bytes\n", list_len);
#endif /* DEBUG */
	attr_list = malloc(list_len);

	ret = listxattr(path, attr_list, list_len);

	if (ret != list_len) {
		printf("length was %d, but only got %d?\n",
			list_len, ret);
	} else {
		ret = 0;
		while (ret < list_len) {
resize:
			attr_len = getxattr(path, attr_list + ret, attr, attr_buf_len);
			if (attr_len == -1) {
				if (errno == ERANGE) {
					free(attr);
					attr_buf_len = getxattr(path, attr_list + ret, NULL, 0);
					attr = malloc(attr_buf_len);
					goto resize;
				}
				printf("error: %m\n");
				return -1;
			}
			printf("%s (%d bytes):\n", attr_list + ret, attr_len);

			if (!strcmp(attr_list + ret, ACL_NFS4_XATTR)) {
				show_nfs4_acl(attr, attr_len, is_dir);
			} else if (!strcmp(attr_list + ret, ACL_SELINUX_XATTR)) {
				show_selinux(attr, attr_len);
			} else if (!strcmp(attr_list + ret, ACL_POSIX_ACCESS)) {
#if DEBUG
				int slen = strlen(ACL_POSIX_ACCESS);

				printf("contents of '%s': ", ACL_POSIX_ACCESS);
				hexprint(attr_list + ret + slen, attr_len - slen);
#endif /* DEBUG */
				show_acl(path, ACL_TYPE_ACCESS);
			} else if (!strcmp(attr_list + ret, ACL_POSIX_DEFAULT)) {
#if DEBUG
				int slen = strlen(ACL_POSIX_DEFAULT);

				printf("contents of '%s': ", ACL_POSIX_DEFAULT);
				hexprint(attr_list + ret + slen, attr_len - slen);
#endif /* DEBUG */
				show_acl(path, ACL_TYPE_DEFAULT);
			} else {
				printf("unsure how to display '%s'\n", attr_list + ret);
			}

//			attr_i = 0;
//			while (attr_i < attr_len) {
//				printf("\t%s\n", attr + attr_i);
//				attr_i += strlen(attr + attr_i) + 1;
//			}
//			printf("%s: %s (%d bytes)\n", attr_list + ret, attr, attr_ret);
			ret += strlen(attr_list + ret) + 1;
		}
	}
	return 0;
}

