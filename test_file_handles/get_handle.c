/*
	Frank Sorenson <sorenson@redhat.com>, 2021

	Test the name_to_handle_at() syscall

	Usage:  get_handle <path> [ <subdir> ]

	TODO: also test open_by_handle_at() syscall and related library calls

*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BUF_SIZE 4096

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define path_have(p)		(p)
#define path_empty(p)		(p && p[0] == '\0')
#define path_null_or_empty(p)	(!p || p[0] == '\0')
#define path_dot(p)		(p && p[0] == '.' && p[1] == '\0')
#define path_empty_or_dot(p)	((!p) || (p && (p[0] == '\0' || (p[0] == '.' && p[1] == '\0'))))
#define path_null_or_empty_or_dot(p)	(!p || p[0] == '\0' || (p[0] == '.' && p[1] == '\0'))
#define path_relative(p)	(p && p[0] != '\0' && p[0] != '/')
#define path_absolute(p)	(p && p[0] == '/')

void do_try_name_to_handle_at(const char *path, const char *subdir, int flags) {
	struct file_handle *fhp = malloc(4096);
	unsigned int fhsize = MAX_HANDLE_SZ;
	int mount_id, dirfd, i;
	char *flags_str;

	if ((dirfd = openat(AT_FDCWD, path, O_RDONLY|O_CLOEXEC|O_PATH)) < 0) {
		printf("error opening '%s': %m\n", path);
		goto out;
	}

	switch (flags) {
		case 0: flags_str = "0"; break;
		case AT_EMPTY_PATH: flags_str = "AT_EMPTY_PATH"; break;
		case AT_SYMLINK_FOLLOW: flags_str = "AT_SYMLINK_FOLLOW"; break;
		case AT_EMPTY_PATH | AT_SYMLINK_FOLLOW: flags_str = "AT_EMPTY_PATH | AT_SYMLINK_FOLLOW"; break;
		default: asprintf(&flags_str, "INVALID: 0x%x", flags); break;
	}
retry_name_to_handle_at:
	fhp->handle_bytes = fhsize;
	if (fhp->handle_bytes > (BUF_SIZE - offsetof(struct file_handle, f_handle))) {
		printf("error...  fhsize of %u is too large\n", fhp->handle_bytes);
		goto out;
	}

	printf("name_to_handle_at(%s/%s) with fhsize %u, flags: %s", path, subdir, fhsize, flags_str);

	if ((name_to_handle_at(dirfd, subdir, fhp, &mount_id, flags)) < 0) {
		if (errno == EOPNOTSUPP) {
			printf(": not supported: %m\n");
			goto out;
		} else if (errno == EOVERFLOW) {
			if (fhp->handle_bytes > MAX_HANDLE_SZ) {
				printf(": EOVERFLOW - returned fhsize of %u - the filesystem may already have filehandles larger than representable within %d bytes (filehandles may be larger than %d bytes)\n",
					fhp->handle_bytes, MAX_HANDLE_SZ, MAX_HANDLE_SZ - 16); /* as of kernel 5.14, 16 bytes */
				goto out;
			} else if (fhp->handle_bytes > fhsize) { /* probably won't happen, since the previous case will likely occur */
				printf(": EOVERFLOW - returned fhsize of %u - extending fhsize to %u\n", fhp->handle_bytes, fhsize);
				goto retry_name_to_handle_at;
			} else {
				printf(": EOVERFLOW - returned fhsize of %u, but called with %u bytes.\n",
					fhp->handle_bytes, fhsize);
				printf("    one of the following is likely true:\n");
				printf("        * no file handle is available for this particular name on a filesystem\n");
				printf("          which normally supports file handle lookup\n");
				printf("        * the filesystem supports both file handles and automount points, and\n");
				printf("          %s is an automount point\n",
					(!strcmp(subdir, "")) ? "the requested name" : subdir);
				goto out;
			}
		} else {
			printf(": error: %m\n");
			goto out;
		}
	} else {
		printf(": success\n");
		printf("mount_id: %d\n", mount_id);
		printf("filehandle size: %u  handle type: %d\n", fhp->handle_bytes, fhp->handle_type);
		printf("handle: ");
		for (i = 0 ; i < fhp->handle_bytes ; i++)
			printf(" %02x", fhp->f_handle[i]);
		printf("\n");
	}
out:
	if ((flags & ~(AT_EMPTY_PATH | AT_SYMLINK_FOLLOW)) != 0)
		free(flags_str);
}

int main(int argc, char *argv[]) {
	if (argc != 2 && argc != 3) {
		printf("Usage: %s <path> [ <subdir> ]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (argc == 2)
		do_try_name_to_handle_at(argv[1], "", AT_EMPTY_PATH);
	else if (argc == 3)
		do_try_name_to_handle_at(argv[1], argv[2], 0);

	return EXIT_SUCCESS;
}
