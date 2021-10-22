/*
	Frank Sorenson <sorenson@redhat.com>, 2021

	Test the name_to_handle_at() syscall

	Usage:  get_handle [ <path> [ <subpath> ] ]

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

int call_name_to_handle_at(const char *path, const char *subpath) {
	char *display_path = NULL;
	char *cwd = NULL;

	struct file_handle *fhp = malloc(BUF_SIZE);
	unsigned int fhsize = MAX_HANDLE_SZ;
	int dfd = AT_FDCWD, ret = EXIT_FAILURE, flags = 0, mount_id, i;
	char *flags_str;


	cwd = get_current_dir_name();
	if (path_have(path)) {
		if (path_empty(path)) {
			path = ".";
		}
		if ((dfd = openat(AT_FDCWD, path, O_RDONLY|O_CLOEXEC|O_PATH)) < 0) {
			if (path_empty_or_dot(path))
				output("error opening the current directory (\"%s\"): %m\n", cwd);
			else
				output("error opening \"%s\": %m\n", path);
			goto out;
		}
	}
	if (path_null_or_empty(subpath)) {
		flags |= AT_EMPTY_PATH;
		subpath = "";
	}
	fhp->handle_bytes = fhsize;

	switch (flags) {
		case 0: flags_str = "0"; break;
		case AT_EMPTY_PATH: flags_str = "AT_EMPTY_PATH"; break;
		case AT_SYMLINK_FOLLOW: flags_str = "AT_SYMLINK_FOLLOW"; break;
		case AT_EMPTY_PATH | AT_SYMLINK_FOLLOW: flags_str = "AT_EMPTY_PATH | AT_SYMLINK_FOLLOW"; break;
		default: asprintf(&flags_str, "INVALID: 0x%x", flags); break;
	}

	// display strings -- what path are we actually looking at?
	if (path_absolute(subpath))
	//	empty		absolute	subpath
	//	absolute	absolute	subpath
	//	relative	absolute	subpath
		display_path = strdup(subpath);
	else if (
		((!path_have(path)) && (!path_have(subpath))) ||
		(path_empty_or_dot(path) && path_null_or_empty_or_dot(subpath))
		)
	//	none		none		cwd
	//	empty		none		cwd
	//	empty		empty		cwd
		display_path = strdup(cwd);
	else if (path_absolute(path) && path_null_or_empty_or_dot(subpath))
	//	absolute	none		path
	//	absolute	empty		path
		display_path = strdup(path);
	else if (path_relative(path) && path_null_or_empty_or_dot(subpath))
	//	relative	none		cwd/path
	//	relative	empty		cwd/path
		asprintf(&display_path, "%s/%s", cwd, path);
	else if (path_absolute(path) && path_relative(subpath))
	//	absolute	relative	path/subpath
		asprintf(&display_path, "%s/%s", path, subpath);
	else if (path_empty_or_dot(path) && path_relative(subpath))
	//	empty		relative	cwd/subpath
		asprintf(&display_path, "%s/%s", cwd, subpath);
	else if (path_relative(path) && path_relative(subpath))
	//	relative	relative	cwd/path/subpath
		asprintf(&display_path, "%s/%s/%s", cwd, path, subpath);
	else
		display_path = strdup("INVALID");
	//	none		empty		"INVALID"
	//	none		absolute	"INVALID"
	//	none		relative	-- INVALID

	output("effective path: \"%s\"\n", display_path);
	output("name_to_handle_at(%d<%s>, \"%s\", file_handle{handle_bytes = %d}, &mount_id, %s)",
		dfd, path, subpath, fhp->handle_bytes, flags_str);

	if ((name_to_handle_at(dfd, subpath, fhp, &mount_id, flags)) < 0) {
		if (errno == EINVAL) {
			output("EINVAL - this should not happen, unless MAX_HANDLE_SZ (%d)\n", MAX_HANDLE_SZ);
			output("  is increased in userspace above the kernel value\n");
		} else if (errno == EOPNOTSUPP)
			output("EOPNOTSUPP - the underlying filesystem may not support filehandles\n");
		else if (errno == ENOENT)
			output("ENOENT - the path \"%s\" may not exist\n", display_path);
		else if (errno == ENOTDIR)
			output("ENOTDIR - a path component of \"%s\" may not be a directory\n", display_path);
		else if (errno == EOVERFLOW) {
			if (fhp->handle_bytes > MAX_HANDLE_SZ) {
				output("EOVERFLOW - the filesystem exports filehandles of %d bytes,", fhp->handle_bytes);
				output("  but the largest size supported is %d bytes\n", MAX_HANDLE_SZ);
			} else {
				output("EOVERFLOW - one of the following is likely true:\n");
				output("\t* no file handle is available for this particular name on a filesystem\n");
				output("\t  which normally supports file handle lookup\n");
				output("\t* the filesystem supports both file handles and automount points, and\n");
				output("\t  %s is an automount point\n", display_path);
			}
		} else
			output("ERROR occurred - %m\n");

	} else {
		output(": success\n");
		output("mount_id: %d  filehandle size: %u  handle type: %d\n", mount_id, fhp->handle_bytes, fhp->handle_type);
		output("handle: ");
		for (i = 0 ; i < fhp->handle_bytes ; i++)
			output(" %02x", fhp->f_handle[i]);
		output("\n");
		ret = EXIT_SUCCESS;
	}
out:
	if (cwd)
		free(cwd);
	if (display_path)
		free(display_path);
	if ((flags & ~(AT_EMPTY_PATH | AT_SYMLINK_FOLLOW)) != 0)
		free(flags_str);
	return ret;
}
int usage(const char *exe, int ret) {
	output("Usage: %s [ <path> [ <subpath> ] ]\n", exe);
	output("\n");
//	output("	no-argument usage
//	output("	one-argument usage
//	output("	two-argument usage

	return ret;
}

int main(int argc, char *argv[]) {
	if (argc == 1)
		call_name_to_handle_at(NULL, NULL);
	else if (argc == 2)
		call_name_to_handle_at(argv[1], NULL);
	else if (argc == 3)
		call_name_to_handle_at(argv[1], argv[2]);
	else
		return usage(argv[0], EXIT_FAILURE);
}
