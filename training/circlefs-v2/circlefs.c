#include "circlefs.h"

struct circlefs_data circlefs_data = {
	.radius = 0,
};

struct circlefs_dirent circlefs_dirents[] = {
	{ .name = ".",		.st = { .st_mode = S_IFDIR | 0555, .st_ino = 1, } },
	{ .name = "..",		.st = { .st_mode = S_IFDIR | 0555, .st_ino = 2, } },
	{ .name = "radius",	.st = { .st_mode = S_IFREG | 0644, .st_ino = 3, } },
	{ .name = "pi",		.st = { .st_mode = S_IFREG | 0444, .st_ino = 4, } },
	{ .name = "π",		.st = { .st_mode = S_IFLNK | 0777, .st_ino = 5, } },
	{ .name = "diameter",	.st = { .st_mode = S_IFREG | 0644, .st_ino = 6, } },
	{ .name = "circumference", .st = { .st_mode = S_IFREG | 0644, .st_ino = 7, } },
	{ .name = "area",	.st = { .st_mode = S_IFREG | 0644, .st_ino = 8, } },
	// sphere attributes
	{ .name = "surface_area", .st = { .st_mode = S_IFREG | 0644, .st_ino = 9, } },
	{ .name = "volume",	.st = { .st_mode = S_IFREG | 0644, .st_ino = 10, } },
};
#define DIRENT_COUNT (ARRAY_SIZE(circlefs_dirents))

// path doesn't matter, since we don't have any subdirs
static int circlefs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t start_offset, struct fuse_file_info *ffi,
		enum fuse_readdir_flags readdir_flags) {

	int offset;

	// The 'start_offset' is used in case our directory listing needs to call
	//     into readdir() more than once.  However, our filesystem is very
	//     small, so we'll probably always start at the beginning of the dir.

	for (offset = start_offset ; offset < DIRENT_COUNT ; offset++) {
		fill_statbuf(&circlefs_dirents[offset]);
		filler(buf, circlefs_dirents[offset].name,
			&circlefs_dirents[offset].st, 0, FUSE_FILL_DIR_PLUS);
	}
	return 0;
}
static int circlefs_getattr(const char *path, struct stat *st,
		struct fuse_file_info *ffi) {
	int i;
	if (!strcmp("/", path))
		path = ".";
	else if (*path == '/') // paths start with '/', so advance to fix that
		path++;
	for (i = 0 ; i < DIRENT_COUNT ; i++)
		if (!strcmp(path, circlefs_dirents[i].name)) {
			fill_statbuf(&circlefs_dirents[i]);
			memcpy(st, &circlefs_dirents[i].st, sizeof(struct stat));
			return 0;
		}
	return -ENOENT;
}
static int circlefs_read(const char *path, char *buf,
	size_t size, off_t off, struct fuse_file_info *ffi) {

	char localbuf[128] = { 0 };
	long double val = NAN;
	int copied;

	// paths start with '/', so advance to fix that
	if (*path == '/')
		path++;

	if (!strcmp(path, "radius"))
		val = circlefs_data.radius;
	else if (!strcmp(path, "pi"))
		val = M_PIf128;
	else if (!strcmp(path, "diameter"))
		val = 2.0 * circlefs_data.radius;
	else if (!strcmp(path, "circumference"))
		val = 2.0 * M_PIf128 * circlefs_data.radius;
	else if (!strcmp(path, "area"))
		val = M_PIf128 * circlefs_data.radius * circlefs_data.radius;
	else if (!strcmp(path, "surface_area"))
		val = 4.0 * M_PIf128 * powl(circlefs_data.radius, 2.0);
	else if (!strcmp(path, "volume"))
		val = (4.0 / 3.0) * M_PIf128 * powl(circlefs_data.radius, 3.0);

	if (isnan(val)) // not a real file
		return -EBADF;

	// try to check whether our value can be expressed as an integer
	uint64_t int_val = val;
	long double tmp = val - int_val;

	if (tmp > 0)
		snprintf(localbuf, sizeof(localbuf) - 1, "%.36Lf", val);
	else
		snprintf(localbuf, sizeof(localbuf) - 1, "%" PRIu64, int_val);

	if (off > strlen(localbuf))
		copied = 0;
	else
		copied = strlen(localbuf) - off;

	if (copied > size)
		copied = size;
	if (copied)
		memcpy(buf, localbuf + off, copied);
	clock_gettime(CLOCK_REALTIME, &circlefs_data.access_time);
	return copied;
}
static int circlefs_write(const char *path, const char *buf,
	size_t size, off_t off, struct fuse_file_info *ffi) {

	char *endptr = NULL;
	long double val;

	if (off != 0) // makes no sense to write anywhere but 0
		return -EINVAL;

	errno = 0;
	val = strtold(buf, &endptr);

        if (errno == ERANGE || // out-of range
			endptr == buf || // empty write or bad value
			val == HUGE_VAL || val == -HUGE_VAL)
                return -EINVAL;

	// paths start with '/', so advance to fix that
	if (*path == '/')
		path++;

	if (!strcmp(path, "radius"))
		circlefs_data.radius = val;
	else if (!strcmp(path, "diameter"))
		circlefs_data.radius = val / 2.0;
	else if (!strcmp(path, "circumference"))
		circlefs_data.radius = val / (2.0 * M_PIf128);
	else if (!strcmp(path, "area"))
		circlefs_data.radius = powl(val / M_PIf128, 0.5);
	else if (!strcmp(path, "surface_area"))
		circlefs_data.radius = sqrtl(val / (M_PIf128 * 4));
	else if (!strcmp(path, "volume"))
		circlefs_data.radius = cbrtl((val * 3.0) / (M_PIf128 * 4.0));
	else // what file is this?
		return -EBADF;

	clock_gettime(CLOCK_REALTIME, &circlefs_data.modify_time);
	return size;
}
static int circlefs_readlink(const char *path, char *buf, size_t size) {
	int i;

	// paths start with '/', so advance to fix that
	if (*path == '/')
		path++;

	if (!strcmp(path, "π")) {
		strncpy(buf, "pi", size - 1);
		if (strlen(buf) < 2)
			return -ENAMETOOLONG;
		return 0;
	}
	for (i = 0 ; i < ARRAY_SIZE(circlefs_dirents) ; i++)
		if (! strcmp(path, circlefs_dirents[i].name))
			return -EINVAL; // not a symlink
	return -ENOENT; // no such file
}
// 'path' is really irrelevant... our filesystem doesn't vary based on the path
static int circlefs_statfs(const char *path, struct statvfs *stbuf) {
	struct statvfs stvfs = {
		.f_bsize = BLOCK_SIZE,
		.f_bfree = 0,
		.f_bavail = 0,
		.f_blocks = DIRENT_COUNT,
		.f_files = DIRENT_COUNT,
		.f_ffree = 0,
		.f_favail = 0,
		.f_flag = ST_NODEV | ST_NOEXEC | ST_NOSUID,
		.f_frsize = 0,
		.f_namemax = 255,
	};
	memcpy(stbuf, &stvfs, sizeof(stvfs));

	return 0;
}

static const struct fuse_operations circlefs_ops = {
	.readdir        = circlefs_readdir,
	.getattr        = circlefs_getattr,
	.read		= circlefs_read,
	.write		= circlefs_write,
	.readlink	= circlefs_readlink,
	.statfs		= circlefs_statfs,
};

int main(int argc, char *argv[]) {
	circlefs_data.uid = getuid();
	circlefs_data.gid = getgid();
	clock_gettime(CLOCK_REALTIME, &circlefs_data.mount_time);
	circlefs_data.modify_time = circlefs_data.access_time = circlefs_data.mount_time;

	return fuse_main(argc, argv, &circlefs_ops, NULL);
}

