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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <linux/fs.h>
#include <sys/vfs.h>
#include <errno.h>
#include <getopt.h>


#define DEBUG 0

#include "listxattr.h"
#include "encdec.h"

#include "posix.h"
#include "ext.h"
#include "nfs4.h"
#include "xfs.h"
#include "ntacl.h"
#include "selinux.h"
#include "capability.h"

#define DEF_VAL_LEN (32)



typedef void *(show_acl_t)(const char *attr_name, const unsigned char *attr_bytes, int len, bool is_dir);

struct show_funcs_struct {
	char *name;
	show_acl_t *show;
} show_funcs[] = {
};

/*
listxattr.c:52:43: warning: initialization of
	‘void ** (*)(const char *, const unsigned char *, int,  _Bool)’
		from incompatible pointer type
	‘void * (*)(const unsigned char *, const unsigned char *, int,  _Bool)’
		[-Wincompatible-pointer-types]
   52 |         { .name = ACL_NFS4_XATTR, .show = show_nfs4_acl },
*/

	// xattr namespaces
	// os2 osx btrfs gnu security system trusted user
	//
	// security namespace
	//   evm
	//   ima
	//   selinux
	//   capability
	//
	//   SMACK64
	//   SMACK64IPIN
	//   SMACK64IPOUT
	//   SMACK64EXEC
	//   SMACK64TRANSMUTE
	//   SMACK64MMAP
	//
	//   apparmor
	//
	// trusted (only accessed by privileged users)
	//   SGI_ACL_DEFAULT
	//   SGI_ACL_FILE
	//
	//
	// user (only regular files or directories,  for sticky directories, only the owner and privileged user can write
	//
	//
	// btrfs
	//   compression
	//
	// system
	//   posix_acl_access
	//   posix_acl_default
	//
	//   nfs4_acl
	//
	//
	/*
#define ACL_NFS4_XATTR          "system.nfs4_acl"
#define ACL_SELINUX_XATTR       "security.selinux"
#define ACL_POSIX_ACCESS        "system.posix_acl_access"
#define ACL_POSIX_DEFAULT       "system.posix_acl_default"
	*/

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
			printf("parsing an acl entry (p_acl: %p)\n", p_acl);
		}

	}

	void show_acl(const char *acl_bytes, int len, acl_type_t type) {
#if DEBUG
		printf("size of 'acl_t' = %ld\n", sizeof(acl_t));
#endif /* DEBUG */
	//	acl_t acl = acl_get_file(path, type);
		acl_t acl = (acl_t)acl_bytes;

		if (acl == NULL) {
			printf("null string given for acl\n");
		} else {
			char *acl_text;
	//		ssize_t acl_len;
#if DEBUG || 1
		int s = acl_size(acl);
		printf("size of this acl: %d\n", s);
		printf("contents of this acl:  ");
		hexprint((unsigned char *)acl, s);
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
	void show_file_acl(const char *path, acl_type_t type) {
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


	void read_decode_ioctl_flags(const char *path, unsigned long fstype) {
		int result;
		int fd;
		int ret;

		fd = open(path, O_RDONLY|O_NONBLOCK);
		ret = ioctl(fd, FS_IOC_GETFLAGS, &result);
		close(fd);

		printf("ioctl returned %d, result: 0x%08x\n", ret, result);
		printf("flags: 0x%08x\n", result);

		printf("fstype: 0x%08lx\n", fstype);

		if (fstype == 0x1234)
			decode_ioctl_flags_ext(result);
	}

	//int decode_this(char *path, char *xattr_name, int len, char *attr_bytes, bool is_dir) {
	//void show_xattr_generic(const char *path, const char *key, char *val_buf, int *val_buf_len) {
	void show_xattr_generic(const char *path, const char *key, int *len, const unsigned char *attr_bytes, bool is_dir) {
		int vallen = getxattr(path, key, NULL, 0);


	//	val_buf = 

		if (vallen + 1 > *len) {
			free_mem(len);
			attr_bytes = malloc(vallen + 1);
			*len = vallen + 1;
		}

		if ((vallen = getxattr(path, key, (char *)attr_bytes, *len)) == -1) {
			perror("getxattr");
		} else {
			if (printable(attr_bytes, *len - 1) && attr_bytes[*len - 1] == '\0')
				printf("%s = '%s'\n", key, attr_bytes);
			else {
				printf("%s = \n", key);
				hexprint_pad("  ", attr_bytes, *len);
				printf("foo");
			}
		}
		printf("bar\n");
	}

static struct option long_opts[] = {
	{ "decode", required_argument, NULL, 'd' },
	{ "list", no_argument, NULL, 'l' },
	{ NULL, 0, 0, 0 },
};



int decode_this(const char *path, char *xattr_name, int len, unsigned char *attr_bytes, bool is_dir) {
	int ret = EXIT_SUCCESS, i;

	for (i = 0 ; i < encdec_count ; i++) {
		char **p = encdec_info[i].xattr_strings;
		while (*p) {
			if (!strcmp(*p, xattr_name)) {
				output("can decode as %s\n", encdec_info[i].name);
				ret += encdec_info[i].decode(xattr_name, attr_bytes, len, is_dir);
				goto out;
			}
			p++;
		}
	}
	ret = EXIT_FAILURE;

out:
	return ret;
}

#define ATTR_LIST_BUF_DEFAULT_LEN 128
#define ATTR_VALUE_BUF_DEFAULT_LEN 512
int listxattrs(const char *path) {
	static int attr_list_buf_len = ATTR_LIST_BUF_DEFAULT_LEN;
	static unsigned char *attr_list_buf = NULL;

	static int attr_value_buf_len = ATTR_VALUE_BUF_DEFAULT_LEN;
	static unsigned char *attr_value_buf = NULL;

	int attr_list_len, ret = EXIT_FAILURE;

//	int val_buf_len = 0;
//	char *val_buf = malloc(DEF_VAL_LEN);

	int attr_len;
	int is_dir = 0;
	struct statvfs stvfs;
	struct statfs stfs;
	struct stat st;

	if (!attr_list_buf)
		attr_list_buf = malloc(attr_list_buf_len);
	if (!attr_value_buf)
		attr_value_buf = malloc(attr_value_buf_len);


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

//	attr = malloc(attr_value_buf_len);
//	do_acl_checks(path);

resize_attr_list_buf:
	if ((attr_list_len = listxattr(path, (char *)attr_list_buf, attr_list_buf_len)) < 0) {
		if (errno == ERANGE) {
			free_mem(attr_list_buf);
			attr_list_buf_len = listxattr(path, NULL, 0);
			attr_list_buf = malloc(attr_list_buf_len);
			goto resize_attr_list_buf;
		}
		printf("listxattr() error: %m\n");
	} else if (attr_list_len == 0) {
		printf("no xattrs for %s\n", path);
		return EXIT_SUCCESS;
	}

#if DEBUG
	printf("listxattr() returned %d bytes\n", attr_list_len);
#endif /* DEBUG */
//	attr_list_buf = malloc(attr_list_buf_len);
//	ret = listxattr(path, attr_list_buf, attr_list_buf_len);

//printf("got listxattr length of %d\n", attr_list_buf_len);


	if (0 && attr_list_len != attr_list_buf_len) {
		printf("length was %d, but only got %d?\n",
			attr_list_buf_len, attr_list_len);
	} else {
//		char *attr_name = strdup(attr_list_buf + ret);
		char *attr_name = strdup((char *)attr_list_buf);
		ret = 0;
		unsigned char *attr_list_buf_ptr = attr_list_buf;
//		while (ret < attr_list_buf_len) {
		while ((attr_list_buf_ptr - attr_list_buf + 1) < attr_list_len) {
			attr_name = strdup((char *)attr_list_buf_ptr);


			if (!strcmp(attr_name, ACL_POSIX_ACCESS)) {
				show_file_acl(path, ACL_TYPE_ACCESS);
			} else if (!strcmp(attr_name, ACL_POSIX_DEFAULT)) {
				show_file_acl(path, ACL_TYPE_DEFAULT);
			} else {
resize_attr_value_buf:
				attr_len = getxattr(path, attr_name, attr_value_buf, attr_value_buf_len);
				if (attr_len == -1) {
					if (errno == ERANGE) {
						free_mem(attr_value_buf);
						attr_value_buf_len = getxattr(path, attr_name, NULL, 0);
						attr_value_buf = malloc(attr_value_buf_len);
						goto resize_attr_value_buf;
					}
					printf("error: %m\n");
					return -1;
				}

//				decode_this(path, strdup(attr_list_buf + ret), attr_len, attr, is_dir);
				decode_this(path, attr_name, attr_len, attr_value_buf, is_dir);
			}

#if 0
			printf("%s (%d bytes):\n", attr_list_buf + ret, attr_len);

			if (!strcmp(attr_list_buf + ret, ACL_NFS4_XATTR)) {
				show_nfs4_acl(attr, attr_len, is_dir);
			} else if (!strcmp(attr_list_buf + ret, ACL_SELINUX_XATTR)) {
				show_selinux(attr, attr_len);
			} else if (!strcmp(attr_list_buf + ret, ACL_POSIX_ACCESS)) {
#if DEBUG
				int slen = strlen(ACL_POSIX_ACCESS);

				printf("contents of '%s': ", ACL_POSIX_ACCESS);
				hexprint(attr_list_buf + ret + slen, attr_len - slen);
#endif /* DEBUG */
				show_acl(path, ACL_TYPE_ACCESS);
			} else if (!strcmp(attr_list_buf + ret, ACL_POSIX_DEFAULT)) {
#if DEBUG
				int slen = strlen(ACL_POSIX_DEFAULT);

				printf("contents of '%s': ", ACL_POSIX_DEFAULT);
				hexprint(attr_list_buf + ret + slen, attr_len - slen);
#endif /* DEBUG */
				show_acl(path, ACL_TYPE_DEFAULT);
			} else
				show_xattr_generic(path, attr_list_buf + ret, val_buf, &val_buf_len);
#endif
			attr_list_buf_ptr += strlen(attr_name) + 1;
			free_mem(attr_name);
		}
	}

	return ret;
}

int decode_string(char *string) {
	int ret = EXIT_FAILURE;
	unsigned char *attr; // the raw bytes, after dehexing or debase64ing
	int attr_len;

	if (strlen(string)) {
//	if (string) {
		char *acl_type_str;
		char *acl_val_str;
		int acl_type_len;
//		char *acl_str_hex = strchr(string, ':');

//		if (!acl_str_hex) // check for an '=' instead
//			acl_str_hex = strchr(string, '=');
		acl_val_str = strchr(string, ':');
		if (!acl_val_str) // check for an '=' instead
			acl_val_str = strchr(string, '=');

		if (!acl_val_str) {
			printf("could not find string to decode:  ACL_TYPE:ACL_VALUE or ACL_TYPE=ACL_VALUE\n");
			return EXIT_FAILURE;
		}

		acl_type_len = acl_val_str - string;
		acl_type_str = strndup(string, acl_type_len);

		printf("xattr name: %s\n", acl_type_str);

		acl_val_str++;
		if (!strncmp(acl_val_str, "0x", 2)) { // decode as hex
			int hex_len;

			acl_val_str += 2;

//			printf("reading in a hex string:\n");
//			hexprint(acl_val_str, strlen(acl_val_str));


			hex_len = strlen(acl_val_str);
			if (hex_len & 1) {
				printf("error: invalid hex string to decode (odd number of hex digits: %d)\n\t%s\n",
					hex_len, acl_val_str);
				goto out;
			}
			attr_len = hex_len / 2;
			attr = dehexlify_string(acl_val_str);
		} else if (!strncmp(acl_val_str, "0s", 2)) { // decode base64

			acl_val_str += 2;

			attr_len = debase64_len(acl_val_str);
			attr = debase64ify(acl_val_str);
		} else {
			printf("unknown string type: '%s'\n", acl_val_str);
			return EXIT_FAILURE;
		}

		if (attr) {
			decode_this("<NONE>", acl_type_str, attr_len, attr, false);
		}
#if 0
		if (acl_str_hex) {

			/* TODO: THIS DOES NOT WORK YET... NEED TO IMPLEMENT __acl_from_xattr ourselves */
//			acl_to_any_text(acl_t acl, const char *prefix, char separator, int options);
//			char *acl = acl_to_any_text(attr, "\n\t", ':', TEXT_ALL_EFFECTIVE);
//			char *acl = acl_to_any_text(attr, "\n\t", ':', TEXT_ALL_EFFECTIVE);

			decode_this("<NONE>", acl_type_str, attr_len, attr, false);
 //int decode_this(char *path, char *xattr_name, int len, char *attr_bytes, bool is_dir) {

			printf("here\n");
		}
#endif
		goto out;
	}

out:
	free_mem(attr);
	return ret;
}




int main(int argc, char *argv[]) {
	int ret = EXIT_FAILURE, arg, i;

#if 0
	const char *data = "ABC123Test Lets Try this' input and see What \"happens\"";
	char       *enc;
	unsigned char *out;
	size_t out_len;


	printf("data:    '%s'\n", data);
	enc = base64ify((unsigned char *)data, strlen(data));
	printf("encoded: '%s'\n", enc);
	printf("decoded size %s data size\n", debase64_len(enc) == strlen(data) ? "==" : "!=");
	out_len = debase64_len(enc) + 1;
	out = debase64ify(enc);
	out[out_len] = '\0';

	printf("dec:    '%s'\n", out);
	printf("data %s decoded\n", strcmp(data, (char *)out) == 0 ? "==" : "!=");

	free_mem(enc);
	free_mem(out);

return EXIT_SUCCESS;
#endif

	while ((arg = getopt_long(argc, argv, "d:l", long_opts, NULL)) != EOF) {
		switch (arg) {
			case 'd':
				ret = decode_string(strdup(optarg));
				goto out;
				break;
			case 'l': {
				output("looks like there are %d encdec types:\n", encdec_count);
				for (i = 0 ; i < encdec_count ; i++) {
					char **p = encdec_info[i].xattr_strings;
					output("%d) %s\n", i, encdec_info[i].name);
						while (*p) {
						output("\t%s\n", *p);
						p++;
					}
				}
			} ; break;
			default:
				printf("usage: %s ...\n", argv[0]);
//				usage(argv[0]);
				goto out;
				break;
		}
	}

	for (i = optind ; i < argc ; i++) {
		ret += listxattrs(argv[i]);
	}


out:
	return 0;
}
