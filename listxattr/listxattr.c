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


void read_decode_ioctl_flags(char *path, __fsword_t fstype) {
	int result;
	int fd;
	int ret;

#define ACL_NFS4_XATTR		"system.nfs4_acl"
#define ACL_SELINUX_XATTR	"security.selinux"
#define ACL_POSIX_ACCESS	"system.posix_acl_access"
#define ACL_POSIX_DEFAULT	"system.posix_acl_default"



	fd = open(path, O_RDONLY|O_NONBLOCK);
	ret = ioctl(fd, FS_IOC_GETFLAGS, &result);
	close(fd);

	printf("ioctl returned %d, result: 0x%08x\n", ret, result);
	printf("flags: 0x%08x\n", result);

	printf("fstype: 0x%08lx\n", fstype);

	if (fstype == 0x1234)
		decode_ioctl_flags_ext(result);
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
	struct statvfs stvfs;
	struct statfs stfs;
	struct stat st;

	ret = stat(path, &st);
	if (ret < 0) {
		printf("Bad path: %s\n", path);
		return -1;
	}
	if (st.st_mode & S_IFDIR)
		is_dir = 1;
	statfs(path, &stfs);
	statvfs(path, &stvfs);

	read_decode_ioctl_flags(path, stfs.f_type);

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

