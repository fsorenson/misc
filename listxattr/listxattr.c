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

#include "listxattr.h"
#include "encdec.h"

#include "ext.h"

#define DEF_VAL_LEN (32)


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

void show_xattr_generic(const char *path, const char *key, int *len, const unsigned char *attr_bytes, bool is_dir) {
	int vallen = getxattr(path, key, NULL, 0);

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

	int attr_len;
	int is_dir = 0;
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

	read_decode_ioctl_flags(path);

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

	if (verbosity > 0)
		printf("listxattr() returned %d bytes\n", attr_list_len);

	if (0 && attr_list_len != attr_list_buf_len) {
		printf("length was %d, but only got %d?\n",
			attr_list_buf_len, attr_list_len);
	} else {
		char *attr_name = strdup((char *)attr_list_buf);
		ret = 0;
		unsigned char *attr_list_buf_ptr = attr_list_buf;
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

				decode_this(path, attr_name, attr_len, attr_value_buf, is_dir);
			}

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
		char *acl_type_str;
		char *acl_val_str;
		int acl_type_len;

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
		goto out;
	}

out:
	free_mem(attr);
	return ret;
}




int main(int argc, char *argv[]) {
	int ret = EXIT_FAILURE, arg, i;

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
