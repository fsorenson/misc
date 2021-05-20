/*
	Frank Sorenson <sorenson@redhat.com>, 2016-

	a C-based fuse filesystem to implement 'circlefs',
	a contrived filesystem that computes circumference,
	diameter, radius, area, etc. when any of the others
	are modified
*/

#define _GNU_SOURCE
#define _XOPEN_SOURCE 500

#define FUSE_USE_VERSION 26

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <limits.h>

#define PRECISION 3

#define LOGFILE "/tmp/circlefs"

struct cfs_info_struct {
	char *root;

	uid_t uid;
	gid_t gid;

	FILE *stdout;
	FILE *stderr;

	long double r;
	long double d;
	long double c;
	long double a;
	long double v;
	long double sa;

	int precision;
};
struct cfs_info_struct cfs_info;

#define CFS_DATA ((struct cfs_info *) fuse_get_context()->private_data)


struct circlefs_file_struct {
	char *name;
	int ino;
	long double(*set)(long double d);
	long double(*get)(void);
};

long double set_r(long double r) {
	cfs_info.r = r;
	cfs_info.d = r * 2.0;
	cfs_info.c = cfs_info.d * M_PI;
	cfs_info.a = M_PI * r * r;
	cfs_info.v = 4.0/3.0 * M_PI * r * r * r;
	cfs_info.sa = 4.0 * M_PI * r * r;
	return r;
}
long double set_d(long double d) {
	set_r(d / 2.0);
	return (cfs_info.d = d);
}
long double set_c(long double c) {
	set_r(c / 2.0 / M_PI);
	return (cfs_info.c = c);
}
long double set_a(long double a) {
	set_r(sqrtl(a / M_PI));
	return (cfs_info.a = a);
}
long double set_v(long double v) {
	set_r(cbrtl( 3.0 / 4.0 * v / M_PI));
	return (cfs_info.v = v);
}
long double set_sa(long double sa) {
	set_r( sqrtl( sa / 4.0 / M_PI ));
	return (cfs_info.sa = sa);
}
long double get_r(void) { return cfs_info.r; }
long double get_d(void) { return cfs_info.d; }
long double get_c(void) { return cfs_info.c; }
long double get_a(void) { return cfs_info.a; }
long double get_v(void) { return cfs_info.v; }
long double get_sa(void) { return cfs_info.sa; }

struct circlefs_file_struct circlefs_files[] = {
	{ .name = "radius",		.ino = 1,	.set = set_r,	.get = get_r }, /* circle */
	{ .name = "diameter",		.ino = 2,	.set = set_d,	.get = get_d }, /* circle */
	{ .name = "circumference",	.ino = 3,	.set = set_c,	.get = get_c }, /* circle */
	{ .name = "area",		.ino = 4,	.set = set_a,	.get = get_a }, /* circle */
	{ .name = "volume",		.ino = 5,	.set = set_v,	.get = get_v }, /* sphere */
	{ .name = "surface_area",	.ino = 6,	.set = set_sa,	.get = get_sa } /* sphere */
};

#define circlefs_file_count	(sizeof(circlefs_files) / sizeof(circlefs_files[0]))

int cfs_get_ino(const char *path) {
	char *cpath = strdup(path);
	char *bname = basename(cpath);
	int i;
	int ret = -1;

	for (i = 0 ; i < circlefs_file_count ; i ++) {
		if (!strcmp(bname, circlefs_files[i].name)) {
			ret = i;
			break;
		}
	}
	free(cpath);
	return ret;
}

static void cfs_fullpath(char fpath[PATH_MAX], const char *path) {
	strcpy(fpath, cfs_info.root);
	strncat(fpath, path, PATH_MAX);
}

int cfs_getattr(const char *path, struct stat *stbuf) {

	memset(stbuf, 0, sizeof(struct stat));

	stbuf->st_uid = cfs_info.uid;
	stbuf->st_gid = cfs_info.gid;
	stbuf->st_size = 4096;
	stbuf->st_blocks = 8;

	if (!strcmp("/", path)) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if ((stbuf->st_ino = cfs_get_ino(path)) >= 0) {
		stbuf->st_mode = S_IFREG | 0644;
		stbuf->st_nlink = 1;
		stbuf->st_size = 4096;
	} else
		return -ENOENT;

	return 0;
}

int cfs_open(const char *path, struct fuse_file_info *fi) {
	int ino = -1;
	unsigned int access_mode, flags;

	if ((ino = cfs_get_ino(path + 1)) < 0)
		return -ENOENT;

	access_mode = fi->flags & O_ACCMODE;
	flags = fi->flags & ~O_ACCMODE;

	/* not going to care about some of these */
	if (flags & (O_APPEND | O_ASYNC | O_CREAT | O_EXCL | O_TRUNC)) {
		fprintf(cfs_info.stderr, "don't like the open file mode, but moving on anyway\n");
	}

	/* not sure what to do with O_RDWR, so just don't */
	if ((access_mode != O_RDONLY) && (access_mode != O_WRONLY))
		return -EACCES;

	return 0;
}

int cfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	size_t len;
	(void) fi;
	int ino = -1;
	long double value;
	char *tmp;

	if ((ino = cfs_get_ino(path + 1)) < 0)
		return -ENOENT;

	value = circlefs_files[ino].get();
	len = asprintf(&tmp, "%.*Lf\n", cfs_info.precision, value);

	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, tmp + offset, size);
	} else
		size = 0;

	free(tmp);
	return size;
}

int cfs_write(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi) {

	int ino = -1;
	long double value;
	char *tmp;
	char *ptr;
	int ret;

	if ((ino = cfs_get_ino(path + 1)) < 0)
		return -ENOENT; /* or maybe EBADF */

	tmp = strndup(buf, size); /* offset really has no meaning in this context */
	value = strtold(tmp, &ptr);

	if (
		((value == 0) && (tmp == ptr)) ||
		(value < 0) ||
		(value == HUGE_VAL) ||
		(value == -HUGE_VAL ) ||
		((value == 0) && (errno == ERANGE))) {

		ret = -EIO;
	} else {
		circlefs_files[ino].set(value);
		ret = strlen(tmp);
	}

	free(tmp);

	return ret;
}

int cfs_truncate(const char *path, off_t newsize) {
	return 0;
}

int cfs_statfs(const char *path, struct statvfs *statv) {
	statv->f_bsize = 4096;
	statv->f_blocks = 8;
	statv->f_bfree = 0;
	statv->f_bavail = 0;
	statv->f_files = circlefs_file_count;
	statv->f_ffree = 0;
	statv->f_favail = 0;
	statv->f_namemax = PATH_MAX;

	return 0;
}

int cfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
	       struct fuse_file_info *fi) {

	int i;

	if (strcmp(path, "/"))
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	for (i = 0 ; i < circlefs_file_count ; i ++) {
		filler(buf, circlefs_files[i].name, NULL, 0);
	}
	return 0;
}

void *cfs_init(struct fuse_conn_info *conn) {

	cfs_info.uid = getuid();
	cfs_info.gid = getgid();
	cfs_info.precision = PRECISION;

	set_r(1);


	if ((cfs_info.stdout = freopen(LOGFILE ".out", "w", stdout)) != 0) {
		setvbuf(stdout, NULL, _IONBF, 0);
	} else {
		printf("Unable to redirect stdout\n");
		cfs_info.stdout = stdout;
	}
	if ((cfs_info.stderr = freopen(LOGFILE ".err", "w", stderr)) != 0) {
		setvbuf(cfs_info.stderr, NULL, _IONBF, 0);
	} else {
		fprintf(stderr, "Unable to redirect stderr\n");
		cfs_info.stderr = stderr;
	}

	return CFS_DATA;
}

int cfs_access(const char *path, int mask) {

	// F_OK tests for the existence of the file.  R_OK, W_OK, and X_OK

	char fpath[PATH_MAX];

	printf("\ncfs_access(path=\"%s\", mask=0%o)\n", path, mask);
	cfs_fullpath(fpath, path);

	return 0;
}

int cfs_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi) {

	return cfs_getattr(path, statbuf);
}

struct fuse_operations cfs_oper = {
  .getattr = cfs_getattr,
  .open = cfs_open,
  .read = cfs_read,
  .write = cfs_write,
  .statfs = cfs_statfs,
  .readdir = cfs_readdir,
  .init = cfs_init,
//  .access = cfs_access,
  .fgetattr = cfs_fgetattr,
  .truncate = cfs_truncate
};

void cfs_usage() {
	fprintf(stderr, "usage:  circlefs [FUSE and mount options] mount_point\n");
	abort();
}

int main(int argc, char *argv[]) {
	int fuse_stat;

	if ((getuid() == 0) || (geteuid() == 0)) {
		fprintf(stderr, "Don't run me as root...  just don't\n");
		return 1;
	}

	if (argc != 2)
		cfs_usage();

	cfs_info.root = realpath(argv[argc-1], NULL);

	// turn over control to fuse
	fprintf(stderr, "about to call fuse_main\n");
	fprintf(stderr, "root directory is %s\n", cfs_info.root);
	fuse_stat = fuse_main(argc, argv, &cfs_oper, &cfs_info);
	fprintf(stderr, "fuse_main returned %d\n", fuse_stat);

	free(cfs_info.root);
	return fuse_stat;
}
