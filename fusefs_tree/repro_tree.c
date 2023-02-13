/*
	Frank Sorenson <sorenson@redhat.com>, 2022

	Fake filesystem tree


	$ gcc -Wall repro_tree.c `pkg-config fuse3 --cflags --libs` -o repro_tree
*/

#define FUSE_USE_VERSION 31

#define USE_RANDOM_DELAY 0

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

//#include <fuse.h>
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#define DEBUG 0

enum fuse_api { lowlevel, highlevel };

struct repro_fs {
	char *exe;
	struct fuse_args args;
	struct fuse_lowlevel_ops ll_ops;
	struct fuse_session *se;
	struct fuse_cmdline_opts cmdline_opts;
	struct fuse_conn_info_opts *conn_info_opts;
	struct fuse_loop_config loop_config;

	// high-level API
	struct fuse_operations ops;

	enum fuse_api api;

	double entry_timeout;
	double attr_timeout;
	uid_t uid;
	gid_t gid;

	uint64_t dir_count;
	uint64_t file_count;
	uint64_t desired_depth;
} repro_fs;

#define DIR_COUNT	(repro_fs.dir_count)
#define FILE_COUNT	(repro_fs.file_count)
#define DESIRED_TREE_DEPTH (repro_fs.desired_depth)

//#define DIR_COUNT	(8UL) /* subdirs in each directory */
//#define FILE_COUNT	(5UL) /* files in each directory */
//#define DESIRED_TREE_DEPTH (15UL)  /* actual tree depth may be limited by # of files/dirs -- will be calculated later */

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#if DEBUG > 0
#define debug_output(args...) output(args)
#else
#define debug_output(args...) do { } while (0)
#endif

uint64_t powu64(uint64_t val, int power) {
	uint64_t ret = val;
	int i;

	if (power == 0)
		return 1;

	for (i = 1 ; i < power ; i++)
		ret *= val;
	return ret;
}

#define min(a,b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a < _b ? _a : _b; \
})
#define max(a,b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a > _b ? _a : _b; \
})

#define free_mem(addr) ({ \
	if (addr) \
		free(addr); \
	addr = NULL; \
	addr; })


#define NBITS2(n) (((n)&2)?1:0)
#define NBITS4(n) (((n)&(0xC))?(2+NBITS2((n)>>2)):(NBITS2((n))))
#define NBITS8(n) (((n)&0xF0)?(4+NBITS4((n)>>4)):(NBITS4((n))))
#define NBITS16(n) (((n)&0xFF00)?(8+NBITS8((n)>>8)):(NBITS8((n))))
#define NBITS32(n) (((n)&0xFFFF0000)?(16+NBITS16((n)>>16)):(NBITS16((n))))
#define NBITS64(n) (((n)&0xffffffff00000000)?(32+NBITS32((n)>>32)):(NBITS32((n))))
#define NBITS(n) ((n)==0?0:NBITS64((n))+1)

#define ROOT_INUM		(2UL)
#define INVALID_PATH		(0xffffffffffffffffUL)
#define INVALID_INUM		(INVALID_PATH)

#define INODE_TYPE_MASK		(0x0000000000000001UL)
#define IROOT_INUUM_MASK	(0x0000000000000002UL)
#define FLAG_BITS		(2UL) /* bits for file/dir and root inode number */
#define FLAG_MASK		((1UL << FLAG_BITS) - 1UL)

#define ENTRIES_PER_DIR		(DIR_COUNT > FILE_COUNT ? DIR_COUNT : FILE_COUNT)

#define BITS_PER_LEVEL		(NBITS(ENTRIES_PER_DIR-1))
#define BITS_PER_DIR		(BITS_PER_LEVEL)

#define DEPTH_BITS		(NBITS(DESIRED_TREE_DEPTH))
#define MAX_POSSIBLE_DEPTH	((64UL - DEPTH_BITS - FLAG_BITS) / BITS_PER_DIR)
#define TREE_DEPTH (DESIRED_TREE_DEPTH < MAX_POSSIBLE_DEPTH ? DESIRED_TREE_DEPTH : MAX_POSSIBLE_DEPTH)

#define MAX_OBJ_NUM		((1UL << BITS_PER_DIR) - 1UL)
#define OBJ_NUM_MASK		(MAX_OBJ_NUM)
#define OBJ_NUM_BITS		(BITS_PER_LEVEL)

#define DEPTH_SHIFT		(FLAG_BITS)
#define DEPTH_MASK		(((1UL << DEPTH_BITS) - 1UL) << DEPTH_SHIFT)

#define LEVEL_SHIFT(level)	(((level) * BITS_PER_DIR) + DEPTH_BITS + FLAG_BITS)

#define depth_to_inum_bits(depth) ((((uint64_t)(depth)) << DEPTH_SHIFT) & DEPTH_MASK)
#define type_dir_to_inum_bits() (0UL)
#define type_file_to_inum_bits() (INODE_TYPE_MASK)
#define obj_num_at_level_to_inum_bits(num, level) (((num) & OBJ_NUM_MASK) << LEVEL_SHIFT((level)))


#define inum_to_obj_num_at_level(_inum, level) ((int)( ((uint64_t)(_inum) >> LEVEL_SHIFT(level)) & OBJ_NUM_MASK))
#define inum_to_depth(inum)	(((inum) & DEPTH_MASK) >> DEPTH_SHIFT)
#define INUM_DEPTH(inum)	((int)(((inum) & DEPTH_MASK) >> DEPTH_SHIFT))

#define inum_is_dir(i)		((!((i) & INODE_TYPE_MASK)))
#define inum_is_file(i)		(!(inum_is_dir((i))))
#define inum_is_root(i)		((i) == ROOT_INUM)

#define TIMESTAMP_TRUNCATE_SECONDS (60*10) /* 10 minutes */

#ifndef FUSE_DEFAULT_INTR_SIGNAL
#define FUSE_DEFAULT_INTR_SIGNAL SIGUSR1
#endif

#define REPRO_FS_ATTR_TIMEOUT	(60.0)
#define REPRO_FS_ENTRY_TIMEOUT	(60.0)


// inode number format example
// assuming 16 files/dirs per directory, and 5 depth bits
// 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
// ........ ........ ........ ........ ........ ........ ........ .......X  0 = dir, 1 = file
// ........ ........ ........ ........ ........ ........ ........ ......X.  0 = no meaning, 2 = root inode (all other bits are zero)
// 11111111 11111111 11111111 11111111 11111111 11111111 11111111 11111111  INVALID_PATH/INVALID_INODE (really, just the 2 LSB are enough)
// ........ ........ ........ ........ ........ ........ ........ .XXXXX..  depth of file/dir
// ........ ........ ........ ........ ........ ........ .....XXX X.......  file or directory number for 1st level object  - /(file|dir)_X
// ........ ........ ........ ........ ........ ........ XXXXX... ........  file or directory number for 2nd level object - /.../(file|dir)_X
// ........ ........ ........ ........ ........ ...XXXXX ........ ........  file or directory number for 3rd level object - /.../.../(file|dir)_X
// ........ ........ ........ ........ ......XX XXX..... ........ ........  file or directory number for 4th level object - /.../... ... /(file|dir)_X
// ........ ........ ........ ........ .XXXXX.. ........ ........ ........  file or directory number for 5th level object - /.../... ... /(file|dir)_X
// ........ ........ ........ ....XXXX X....... ........ ........ ........  file or directory number for 6th level object - /.../... ... /(file|dir)_X
// ........ ........ .......X XXXX.... ........ ........ ........ ........  file or directory number for 7th level object - /.../... ... /(file|dir)_X
// ........ ........ ..XXXXX. ........ ........ ........ ........ ........  file or directory number for 8th level object - /.../... ... /(file|dir)_X

// ........ .....XXX XX...... ........ ........ ........ ........ ........  file or directory number for 9th level object - /.../... ... /(file|dir)_X
// ........ XXXXX... ........ ........ ........ ........ ........ ........  file or directory number for 10th level object - /.../... ... /(file|dir)_X
// ...XXXXX ........ ........ ........ ........ ........ ........ ........  file or directory number for 11th level object - /.../... ... /(file|dir)_X
// ........ ........ ........ ........ ........ ........ ........ ........  file or directory number for 12th level object - /.../... ... /(file|dir)_X (only if directories contain fewer entries)
// ........ ........ ........ ........ ........ ........ ........ ........  file or directory number for 13th level object - /.../... ... /(file|dir)_X


int usage(void) {

	output("usage: %s [<options>] <mountpoint>\n\n", repro_fs.exe);
	fuse_cmdline_help();
	fuse_lib_help(&repro_fs.args);
	output("\n");
	fuse_lowlevel_help();
	return EXIT_SUCCESS;
}

struct repro_fh {
	uint64_t ino;
};

uint64_t calc_inodes(void) {
	static uint64_t total_inodes = 0;

	if (total_inodes)
		return total_inodes;

	uint64_t ndirs = 1;
	uint64_t nfiles;
	int i;

	for (i = 1 ; i < TREE_DEPTH ; i++) {
		ndirs += powu64(DIR_COUNT, i);
	}

	output("for %d levels with %d dirs: %ld total dirs\n",
		(int)TREE_DEPTH, (int)DIR_COUNT, ndirs);

	nfiles = FILE_COUNT * ndirs;
	output("for %d levels with %d dirs and %d files/dir: %ld total files\n",
		(int)TREE_DEPTH, (int)DIR_COUNT, (int)FILE_COUNT, nfiles);

	output("total: %lu\n", ndirs + nfiles);
	total_inodes = ndirs + nfiles;
	return total_inodes;
}

static char *mode_bits[] = { "---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx" };

char *mode_bits_string(char *buf, int mode) {
	memcpy(buf, mode_bits[(mode & S_IRWXU) >> 6], 3);
	memcpy(buf + 3, mode_bits[(mode & S_IRWXG) >> 3], 3);
	memcpy(buf + 6, mode_bits[mode & S_IRWXO], 3);

	if (mode & S_ISUID)
		buf[2] = buf[2] == 'x' ? 's' : 'S';
	if (mode & S_ISGID)
		buf[5] = buf[5] == 'x' ? 's' : 'S';
	if (mode & S_ISVTX)
		buf[8] = buf[8] == 'x' ? 't' : 'T';

	buf[9] = '\0';
	return buf;
}
char mode_type_char(int mode) {
	switch (mode & S_IFMT) {
		case S_IFREG: return '-'; break;
		case S_IFDIR: return 'd'; break;
		case S_IFLNK: return 'l'; break;
		case S_IFBLK: return 'b'; break;
		case S_IFCHR: return 'c'; break;
		case S_IFIFO: return 'p'; break;
		case S_IFSOCK: return 's'; break;
		default: return '?'; break;
	}
}

#if USE_RANDOM_DELAY
#define random_delay() do { \
	struct timespec ts; \
	clock_gettime(CLOCK_REALTIME, &ts); \
	uint32_t rand_usec = (ts.tv_nsec >> 4) % 50; \
	usleep(rand_usec); \
} while (0)
#else
#define random_delay() do { } while (0)
#endif

#if DEBUG
void print_statbuf(const char *path, struct stat *st) {
	char mode_string[11];
	mode_string[0] = mode_type_char(st->st_mode);
	mode_bits_string(mode_string + 1, st->st_mode);

	output("path: %s - major:minor %d:%d, ino: 0x%016lx, mode: %o = %s\n",
		path, major(st->st_dev), minor(st->st_dev), st->st_ino, st->st_mode,
		mode_string);
	output("    st_nlink: %ld\n", st->st_nlink);
}
#else
#define print_statbuf(path,st) do {} while (0)
#endif


char *inum_to_path(uint64_t inum) {
	char full_path[4096] = { 0 }, *path_ptr = full_path;
//	char *final_type_str = inum_is_dir(inum) ? "dir" : "file";
	int depth = inum_to_depth(inum);
	int level;

	if (inum == 1)
		inum = ROOT_INUM;

	if (inum == ROOT_INUM)
		return strdup("/");

	for (level = 1 ; level <= depth ; level++) {
		bool internal = (level == depth) ? false : true;
		char *type_str = internal ? "dir" :
			inum_is_dir(inum) ? "dir" : "file";

		uint64_t obj_num = inum_to_obj_num_at_level(inum, level);

		debug_output("%s - internal: %d, inum_is_dir: %d, inum_is_file: %d\n", __func__, internal, inum_is_dir(inum), inum_is_file(inum)); 
		debug_output("%s - object %d at level %d: %s -  0x%016lx\n", __func__, (int)obj_num, level, type_str, obj_num_at_level_to_inum_bits(obj_num, level));

		*path_ptr++ = '/';
		path_ptr += snprintf(path_ptr, sizeof(full_path) - (path_ptr - full_path), "%s_%lu", type_str, obj_num);
		
		if (path_ptr >= full_path + sizeof(full_path))
			break;
	}
	*path_ptr++ = '\0';
	return strdup(full_path);
}

#if 0 && DEBUG
#define inum_dump(inum) do { \
	char full_path[4096], *path_ptr = full_path; \
	char *final_typ_str = inum_is_dir((inum)) ? "dir" : "file"; \
	int depth = inum_to_depth((inum)); \
	int level; \
	\
	for (level = 0 ; level < depth ; level++) { \
		int internal = level == depth - 1 ? 0 : 1; \
		*path_ptr++ = '/'; \
		char *typ_str = internal ? "dir" : final_typ_str; \
		uint64_t obj_num = inum_to_obj_num_at_level((uint64_t)(inum), (uint64_t)level); \
		path_ptr += snprintf(path_ptr, sizeof(full_path) - (path_ptr - full_path), "%s_%lu", typ_str, obj_num); \
		if (path_ptr >= full_path + sizeof(full_path)) \
			break; \
	} \
	*path_ptr++ = '\0'; \
	output("inum 0x%016lx - %s\n", (inum), full_path); \
	output("\n"); \
} while (0)
#endif


int path_depth(const char *path) {
	const char *p = path, *p2;
	int depth = 0, len = strlen(path);

	if (!strcmp("/", path))
		return 0;

	while (p < path + len) {
		p2 = strchr(p, '/');
		if (! p2)
			break;
		p = p2 + 1;
		depth++;
	}
	return depth;
}

#define ret_val_out(val) do { \
	ret = (val); \
	line_num = __LINE__; \
	goto out; \
} while (0)

//int check_path(const char *path) {
int validate_path(const char *path, uint64_t *inum) {
	int len = strlen(path), depth = 0, num;
	const char *p = path, *p2;
	int line_num = 0, ret = 0;

	*inum = 0;

	if (*p != '/')
		ret_val_out(-EINVAL);

	if (!strcmp("/", path) || !strcmp("", path)) {
		*inum = ROOT_INUM;
		goto out_return;
	}
	p++;
	while (p < path + len) {
		depth++;

		if (depth > TREE_DEPTH + 1)
			ret_val_out(-ENOENT);

		if (!strncmp(p, "dir_", 4)) { // directory component

			if (depth >= TREE_DEPTH) // only files at the leaf
				ret_val_out(-ENOENT);

			p += 4;
			num = strtol(p, (char **)&p2, 10);
			if (p == p2) // no digits?
				ret_val_out(-ENOENT);
			p = p2;

			if (num > DIR_COUNT - 1 || num < 0)
				ret_val_out(-ENOENT);
			if (*p != '/' && *p != '\0')
				ret_val_out(-ENOENT);

			debug_output("got num %d for path '%s' (dir) level %d - bits: 0x%016lx\n",
				num, path, depth, obj_num_at_level_to_inum_bits(num, depth));

			*inum |= obj_num_at_level_to_inum_bits(num, depth);

			if (*p == '\0')
				*inum |= type_dir_to_inum_bits();

			p++; // eat the next '/'

		} else if (!strncmp(p, "file_", 5)) { // file component
			p += 5;
			num = strtol((char *)p, (char **)&p2, 10);
			if (p == p2) // no digits
				ret_val_out(-ENOENT);
			p = p2;
			if (num > FILE_COUNT - 1 || num < 0)
				ret_val_out(-ENOENT);
			if (*p != '\0')
				ret_val_out(-ENOTDIR);

			debug_output("got num %d for path '%s' (file) level %d - bits: 0x%016lx\n",
				num, path, depth, obj_num_at_level_to_inum_bits(num, depth) | type_file_to_inum_bits());

			*inum |= obj_num_at_level_to_inum_bits(num, depth) | type_file_to_inum_bits();

		} else {
			ret_val_out(-ENOENT);

		}
	}
out:
	if (!ret) {
		*inum |= depth_to_inum_bits(depth);
	} else {
		output("%s(%s) returning %s at line %d\n", __func__, path, strerror(-ret), line_num);
		fflush(stdout);
	}
out_return:
	return ret;
}

int check_path(const char *path) {
	uint64_t inum;

	return validate_path(path, &inum);
}
uint64_t get_path_inum(const char *path) {
	uint64_t inum;
	int ret;

	ret = validate_path(path, &inum);
	if (ret == 0)
		return inum;
	return INVALID_PATH;
}
bool final_path_element_is_dir(const char *path) {
	const char *last_element;

	if (!path || path[0] == '\0' || !strcmp("/", path))
		return true; // just pretend null or empty path is '/'

	last_element = strrchr(path, '/');
	if (last_element == NULL)
		last_element = path;
	else
		last_element++;

	if (!strncmp(last_element, "dir_", 4))
		return true;
	return false;
}

struct timespec trunc_timestamp(struct timespec ts) {
	__kernel_time_t seconds = ts.tv_sec % (TIMESTAMP_TRUNCATE_SECONDS);
	ts.tv_sec -= seconds;
	ts.tv_nsec = 0;

	return ts;
}

uint64_t do_lookup(uint64_t parent_inum, const char *parent_path_entry, const char *dirent_name, struct fuse_entry_param *e) {
	char *full_path = NULL, *parent_path = NULL, *p;
	uint64_t ret = INVALID_PATH;
	bool parent_path_from_inum = false;
	struct timespec ts;

	// nothing to work with
	if ((parent_inum == INVALID_INUM || parent_inum == 0) && (!parent_path_entry || parent_path_entry[0] != '/')) {
		output("%s - error: parent inode number and parent path are both bogus\n", __func__);
		goto out;
	}

	if (!parent_path_entry || parent_path_entry[0] == '\0') {
		parent_path = inum_to_path(parent_inum); // allocated
		parent_path_from_inum = true;
	} else
		parent_path = strdup(parent_path_entry); // allocated


	if (dirent_name && dirent_name[0] != '\0' && !final_path_element_is_dir(parent_path)) {
		output("%s - error: internal path element of '%s/%s' is not a directory\n",
			__func__, parent_path, dirent_name);
		goto out;
	}

	if (dirent_name && !strcmp("..", dirent_name) && !strcmp("/", parent_path)) { // outside our fs, but we have to return it anyway
		ret = 0;
		goto set_attrs;
	}

	if (!dirent_name || dirent_name[0] == '\0' || !strcmp(".", dirent_name)) {
		full_path = strdup(parent_path);
	} else if (!strcmp("..", dirent_name)) {
		p = strrchr(parent_path, '/');

		if (p == parent_path)
			full_path = strdup("/");
		else
			full_path = strndup(parent_path, p - parent_path);
	} else if (!strcmp("/", parent_path))
		asprintf(&full_path, "/%s", dirent_name);
	else 
		asprintf(&full_path, "%s/%s", parent_path, dirent_name);

	if (parent_path_from_inum) {
		debug_output("%s - resolved parent inum 0x%016lx tto path '%s', and '%s/%s' to '%s'\n",
			__func__, parent_inum, parent_path, parent_path, dirent_name, full_path);
	} else {
		debug_output("%s - resolved '%s/%s' to '%s'\n",
			__func__, parent_path, dirent_name, full_path);
	}

	if (check_path(full_path)) {
		output("%s - error: path '%s' is invalid or does not exist\n",
			__func__, full_path);
		goto out;
	}
	ret = get_path_inum(full_path);
	debug_output("%s - path '%s' has inode number 0x%016lx\n",
		__func__, full_path, ret);

set_attrs:
	clock_gettime(CLOCK_REALTIME, &ts);

	*e = (struct fuse_entry_param){
		.ino = ret,
		.attr_timeout = repro_fs.attr_timeout,
		.entry_timeout = repro_fs.entry_timeout,
		.generation = 1,
		.attr =  {
			.st_ino = ret,
			.st_size = 4096,
			.st_blocks = 1,
			.st_uid = repro_fs.uid,
			.st_gid = repro_fs.gid,
			.st_atim = ts,
			.st_ctim = trunc_timestamp(ts),
			.st_mtim = trunc_timestamp(ts),
			.st_blksize = 42,
			.st_dev = makedev(42, 42),
		}
	};

	if (inum_is_dir(ret)) {
		e->attr.st_mode = 0755 | S_IFDIR;
		e->attr.st_nlink = 2;
	} else {
		e->attr.st_mode = 0444 | S_IFREG;
		e->attr.st_nlink = 1;
	}

out:
	free_mem(parent_path);
	free_mem(full_path);
	return ret;
}

uint64_t get_dirent_inum(const char *path, const char *dirent_name) {
	char full_path[4096], *p2;
	uint64_t inum;

	if (!strcmp(".", dirent_name) || dirent_name[0] == '\0')
		strcpy(full_path, path);
	else if (!strcmp("/", path) && !strcmp("..", dirent_name))
		return INVALID_PATH; // we can't know this
	else if (!strcmp("..", dirent_name)) {
		p2 = strrchr(path, '/');
		strncpy(full_path, path, p2 - path);
		full_path[p2 - path] = '\0';
	} else if (!strcmp("/", path)) { // avoid double '/'
		snprintf(full_path, sizeof(full_path), "/%s", dirent_name);
	} else {
		snprintf(full_path, sizeof(full_path), "%s/%s", path, dirent_name);
	}

	// in case we had something like '/dir_0' and '..'
	if (full_path[0] == '\0') {
		full_path[0] = '/';
		full_path[1] = '\0';
	}

	debug_output("\n%s - full_path: '%s'\n", __func__, full_path);

	inum = get_path_inum(full_path);

	debug_output("\nget_dirent_inum('%s', '%s') = '%s' - 0x%016lx\n",
		path, dirent_name, full_path, inum);
	return inum;
}


#define REPRO_FS_OPT(t, p, v) { t, offsetof(struct repro_fs, p), v }
static const struct fuse_opt repro_ll_opts[] = {
	REPRO_FS_OPT("entry_timeout=%lf",	entry_timeout,	0),
	REPRO_FS_OPT("attr_timeout=%lf",	attr_timeout,	0),
	REPRO_FS_OPT("uid=%d",			uid,		0),
	REPRO_FS_OPT("gid=%d",			gid,		0),
	FUSE_OPT_END
};


static void repro_ll_init(void *userdata, struct fuse_conn_info *conn) {
//struct fuse_conn_info_opts *opts = (struct fuse_conn_info_opts*)userdata;

	output("%s\n", __func__);

//	conn->want |= FUSE_CAP_PARALLEL_DIROPS;

	output("attr timeout: %lf\n", repro_fs.attr_timeout);
	output("entry timeout: %lf\n", repro_fs.entry_timeout);

	fuse_apply_conn_info_opts(repro_fs.conn_info_opts, conn);

//	if (conn->capable & 

/*
                if (arg->flags & FUSE_DO_READDIRPLUS)
                        se->conn.capable |= FUSE_CAP_READDIRPLUS;
                if (arg->flags & FUSE_READDIRPLUS_AUTO)
                        se->conn.capable |= FUSE_CAP_READDIRPLUS_AUTO;

                if (arg->flags & FUSE_PARALLEL_DIROPS)
                        se->conn.capable |= FUSE_CAP_PARALLEL_DIROPS;

                if (arg->flags & FUSE_NO_OPENDIR_SUPPORT)
                        se->conn.capable |= FUSE_CAP_NO_OPENDIR_SUPPORT;
                if (!(arg->flags & FUSE_MAX_PAGES)) {
*/

}

static int repro_getattr(const char *path, struct stat *stbuf,
		       struct fuse_file_info *ffi) {
	struct timespec ts;
	(void) ffi;
	int ret;

	memset(stbuf, 0, sizeof(struct stat));

	stbuf->st_blocks = 1;
	stbuf->st_uid = repro_fs.uid;
	stbuf->st_gid = repro_fs.gid;
	clock_gettime(CLOCK_REALTIME, &ts);
	stbuf->st_atim = ts;
	stbuf->st_ctim = stbuf->st_mtim = trunc_timestamp(ts);
	stbuf->st_nlink = 1;

	if ((ret = check_path(path)))
		return ret;

	if (!strcmp(path, "/")) {
		stbuf->st_mode = 0755 | S_IFDIR;
		stbuf->st_nlink = 2;
	} else {
		char *last_component = strrchr(path, '/');
		last_component++;

		if (!strncmp(last_component, "file_", 5)) {
			stbuf->st_size = strlen(path) + 15;
			stbuf->st_mode = 0444 | S_IFREG;
		} else if (!strncmp(last_component, "dir_", 4)) {
			stbuf->st_size = 4096;
			stbuf->st_mode = 0555 | S_IFDIR;
			stbuf->st_nlink = 2;
		} else
			return -ENOENT;
	}
	stbuf->st_ino = get_path_inum(path);

#if DEBUG > 1
	debug_output("%s - '%s' - inum: 0x%016lx\n", __func__, path, stbuf->st_ino);

	char *reconverted_path = inum_to_path(stbuf->st_ino);
	debug_output("%s -  path '%s' has inum 0x%016lx, which should be '%s'\n",
		__func__, path, stbuf->st_ino, reconverted_path);

	free(reconverted_path);
#endif
	return 0;
}

uint64_t get_dirent_stat(const char *path, const char *dirent_name, struct stat *st) {
	char *full_path = NULL;
	uint64_t inum;

	debug_output("\n\n%s - '%s' '%s'\n", __func__, path, dirent_name);
	if ((inum = get_dirent_inum(path, dirent_name)) != INVALID_PATH) {

		debug_output("\n%s - back from get_dirent_inum: 0x%016lx\n", __func__, inum);

		full_path = inum_to_path(inum);
		debug_output("%s - full path determined to be '%s'\n", __func__, full_path);
		repro_getattr(full_path, st, NULL);
	}

	free_mem(full_path);
	return inum;
}

static void repro_ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *ffi) {
	struct stat stbuf;
	char *path = NULL;

	memset(&stbuf, 0, sizeof(stbuf));
	debug_output("ino: 0x%016lx\n", ino);

	if (ino == 1) {
		if (ffi)
			ffi->fh = ROOT_INUM;
		path = strdup("/");
	} else
		path = inum_to_path(ino);

	repro_getattr(path, &stbuf, NULL);
	print_statbuf(path, &stbuf);
	fuse_reply_attr(req, &stbuf, REPRO_FS_ATTR_TIMEOUT);

//	fuse_reply_err(req, ENOENT);
	free_mem(path);
}

static void repro_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
	struct fuse_entry_param e;
	char *parent_path = NULL;
	uint64_t inum;

	debug_output("%s - parent: 0x%016lx, name: '%s'\n", __func__, parent, name);

	memset(&e, 0, sizeof(e));
	if (parent == 1)
		parent_path = strdup("/");
	else
		parent_path = inum_to_path(parent);

	if ((inum = get_dirent_stat(parent_path, name, &e.attr)) == INVALID_PATH)
		goto out_noent;

	e.attr_timeout = repro_fs.attr_timeout;
	e.entry_timeout = repro_fs.entry_timeout;

	e.ino = inum;

#if DEBUG
print_statbuf("some path", &e.attr);
#endif
	fuse_reply_entry(req, &e);
out:
	free_mem(parent_path);
	return;
out_noent:
	fuse_reply_err(req, ENOENT);
	goto out;
}

#define fuse_get_direntry_len(plus, name) ({ plus ? fuse_add_direntry_plus(NULL, NULL, 0, name, NULL, 0) : fuse_add_direntry(NULL, NULL, 0, name, NULL, 0); })

#define fuse_add_direntry_wrapper(plus, parent_path, name, req, bufp, bufsize, off) ({ \
	struct fuse_entry_param e; \
	\
	uint64_t inum; \
	int copied_len = 0, entry_len = fuse_get_direntry_len(plus, name); \
	\
	if (entry_len > bufsize) \
		goto full; \
	\
	if (((inum = do_lookup(0, parent_path, name, &e)) != INVALID_PATH) || \
			(!strcmp(parent_path, "/") && strcmp(name, ".."))) { \
		if (plus) { \
			copied_len = fuse_add_direntry_plus(req, bufp, (bufsize), name, &e, off); \
			debug_output("%s - adding direntryplus for parent directory '%s' - '%s' (inum 0x%016lx) - %d bytes copied\n", \
				__func__, parent_path, name, inum, copied_len); \
		} else { \
			copied_len = fuse_add_direntry(req, bufp, (bufsize), name, &e.attr, off); \
			debug_output("%s - adding direntry for parent directory '%s' - '%s' (inum 0x%016lx) - %d bytes copied\n", \
				__func__, parent_path, name, inum, copied_len); \
		} \
	} \
	copied_len; \
})

static void repro_do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t start_offset, struct fuse_file_info *ffi, bool plus) {
	char *path = NULL;
	char dirent_name[32];
	uint64_t inum = 0;
	char *buf, *p;
	int current_offset = 0;
	int err, i;

	if (!ffi) {
		err = ENOENT;
		goto err;
	}

	if (ino < ROOT_INUM)
		ino = ROOT_INUM;
	if (ffi->fh < ROOT_INUM)
		ffi->fh = ROOT_INUM;

	inum = ffi->fh;
	path = inum_to_path(inum);

	debug_output("\n\n>> %s(size: %lu)  ***************************\n - inum: 0x%016lx, path: %s\n", __func__, size, inum, path);

	if (!(buf = calloc(1, size))) {
		err = ENOMEM;
		goto err;
	}
	p = buf;

        if (current_offset >= start_offset)
		p += fuse_add_direntry_wrapper(plus, path, ".", req, p, (size - (p - buf)), current_offset);
	current_offset += fuse_get_direntry_len(plus, ".");
	if (current_offset >= start_offset)
		p += fuse_add_direntry_wrapper(plus, path, "..", req, p, (size - (p - buf)), current_offset);
	current_offset += fuse_get_direntry_len(plus, "..");

	for (i = 0 ; i < FILE_COUNT ; i++) {
		snprintf(dirent_name, sizeof(dirent_name), "file_%d", i);
		if (current_offset >= start_offset)
			p += fuse_add_direntry_wrapper(plus, path, dirent_name, req, p, (size - (p - buf)), current_offset);
		current_offset += fuse_get_direntry_len(plus, dirent_name);
	}

	if (path_depth(path) < TREE_DEPTH - 1) {
		for (i = 0 ; i < DIR_COUNT ; i++) {
			snprintf(dirent_name, sizeof(dirent_name), "dir_%d", i);
			if (current_offset >= start_offset)
				p += fuse_add_direntry_wrapper(plus, path, dirent_name, req, p, (size - (p - buf)), current_offset);
			current_offset += fuse_get_direntry_len(plus, dirent_name);
		}
	}

full:
	ffi->cache_readdir = 1;
	ffi->keep_cache = 0;
	fuse_reply_buf(req, buf, p - buf);

out:
	debug_output("<< %s copied %ld bytes ********************************\n", __func__, p - buf);
	free_mem(buf);
	free_mem(path);
	return;
err:
	fuse_reply_err(req, err);
	goto out;
}
static void repro_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t start_offset, struct fuse_file_info *ffi) {
	repro_do_readdir(req, ino, size, start_offset, ffi, false);
}
static void repro_ll_readdir_plus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t start_offset, struct fuse_file_info *ffi) {
	repro_do_readdir(req, ino, size, start_offset, ffi, true);
}

static void repro_ll_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *ffi) {
	char *path = NULL;

	debug_output("%s - req: %p, fuse_ino_t - 0x%016lx, fuse_file_info - %p\n",
		__func__, req, ino, ffi);

	if (ino == 1)
		path = strdup("/");
	else
		path = inum_to_path(ino);

	if (!ffi) {
		output("hmm... ffi is NULL\n");
		fuse_reply_err(req, ENOENT);
	} else if (path == NULL) {
		fuse_reply_err(req, ENOENT);
	} else {
		ffi->fh = get_path_inum(path);

		ffi->cache_readdir = 1;

		fuse_reply_open(req, ffi);
	}

	free_mem(path);
}
static void repro_ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *ffi) {
	char *path = NULL;

	debug_output("%s - req: %p, fuse_ino_t - 0x%016lx, fuse_file_info - %p\n",
		__func__, req, ino, ffi);

	if (ino == 1)
		path = strdup("/");
	else
		path = inum_to_path(ino);

	if (!ffi) {
		output("hmm... ffi is NULL\n");
		fuse_reply_err(req, ENOENT);
	} else if (path == NULL)
		fuse_reply_err(req, ENOENT);
	else {
		ffi->fh = get_path_inum(path);
//		ffi->cache_readdir = 1;
//		ffi->keep_cache = 1;
		fuse_reply_open(req, ffi);
	}
	free_mem(path);
}

static void repro_ll_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *ffi) {
	fuse_reply_err(req, 0);
}


int repro_fuse_main_ll(int argc, char *argv[]) {
	int res;

	if ((fuse_opt_parse(&repro_fs.args, &repro_fs, repro_ll_opts, NULL)) == -1)
		goto out_free;

	if ((repro_fs.conn_info_opts = fuse_parse_conn_info_opts(&repro_fs.args)) == NULL)
		return EXIT_FAILURE;

	if (repro_fs.cmdline_opts.show_help) {
		usage();
		fuse_cmdline_help();
		fuse_lowlevel_help();
		res = EXIT_SUCCESS;
		goto out_free;
	}
	if (repro_fs.cmdline_opts.show_version) {
		output("FUSE library version %s\n", fuse_pkgversion());
                fuse_lowlevel_version();
		res = EXIT_SUCCESS;
		goto out_free;
	}

	if (! repro_fs.cmdline_opts.mountpoint) {
		usage();
		fuse_log(FUSE_LOG_ERR, "error: no mountpoint specified\n");
		res =  EXIT_FAILURE;
		goto out_free;
	}

//	if (fuse_opt_parse(args, &fuse->conf, fuse_lib_opts, fuse_lib_opt_proc) == -1)
//		goto out;

	if ((repro_fs.se = fuse_session_new(&repro_fs.args, &repro_fs.ll_ops, sizeof(repro_fs.ll_ops), NULL)) == NULL) {
		fuse_log(FUSE_LOG_ERR, "error creating fuse session\n");
		res = EXIT_FAILURE;
		goto out_free;
	}

	if (fuse_set_signal_handlers(repro_fs.se) != 0) {
		fuse_log(FUSE_LOG_ERR, "error setting signal handlers\n");
		res = EXIT_FAILURE;
		goto out_session_destroy;
	}

	if ((fuse_session_mount(repro_fs.se, repro_fs.cmdline_opts.mountpoint)) != 0) {
		fuse_log(FUSE_LOG_ERR, "error mounting\n");
		res = EXIT_FAILURE;
		goto out_remove_signal_handlers;
	}
	if ((fuse_daemonize(repro_fs.cmdline_opts.foreground))) {
		res = EXIT_FAILURE;
		goto out_session_unmount;
	}

	if (repro_fs.cmdline_opts.singlethread)
		res = fuse_session_loop(repro_fs.se);
	else {
		repro_fs.loop_config.clone_fd = repro_fs.cmdline_opts.clone_fd;
		repro_fs.loop_config.max_idle_threads = repro_fs.cmdline_opts.max_idle_threads;
		res = fuse_session_loop_mt(repro_fs.se, repro_fs.loop_config.clone_fd);
	}
	if (res)
		res = 7;

out_session_unmount:
	fuse_session_unmount(repro_fs.se);

out_remove_signal_handlers:
	fuse_remove_signal_handlers(repro_fs.se);

out_session_destroy:
	fuse_session_destroy(repro_fs.se);

out_free:
	free_mem(repro_fs.conn_info_opts);

	free_mem(repro_fs.cmdline_opts.mountpoint);

	fuse_opt_free_args(&repro_fs.args);

	free_mem(repro_fs.exe);

	return res ? EXIT_FAILURE : EXIT_SUCCESS;
}
static void fill_statvfs(struct statvfs *stbuf) {
	static uint64_t total_inodes = 0;
	if (total_inodes == 0)
		total_inodes = calc_inodes();

	struct statvfs stvfs = {
		.f_bsize = 42,			// block size
		.f_frsize = 42,			// fragment size

		.f_blocks = total_inodes,	// size of fs in f_frsize units

		.f_bfree = 0,			// # of free blocks
		.f_bavail = 0,			// # of free blocks (unpriv)

		.f_files = total_inodes,	// # of inodes
		.f_ffree = 0,			// # of free inodes
		.f_favail = 0,			// # of free inodes (unpriv)

		.f_flag = 0,
		.f_namemax = 255,
		.f_fsid = 0x4242
	};
	memcpy(stbuf, &stvfs, sizeof(struct statvfs));
}
static void repro_ll_statfs(fuse_req_t req, fuse_ino_t ino) {
	struct statvfs stvfs;

	fill_statvfs(&stvfs);
	fuse_reply_statfs(req, &stvfs);
}
static int repro_hl_statfs(const char *path, struct statvfs *stbuf) {
	fill_statvfs(stbuf);

	return 0;
}

static int repro_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
	off_t start_offset, struct fuse_file_info *ffi, enum fuse_readdir_flags readdir_flags) {

	struct fuse_entry_param e;
	int current_offset = 0;
	uint64_t inum = 0;
	int ret, i;

	// currently not doing readdirplus, regardless of flags
	if ((readdir_flags & FUSE_READDIR_PLUS) == FUSE_READDIR_PLUS)
		debug_output("%s - supposed to use readdirplus\n", __func__);

	debug_output("%s - path: %s - start offset: %ld, ffi->fh: 0x%" PRIx64 "\n",
		__func__, path, start_offset, ffi->fh);


	if (validate_path(path, &inum)) {
		output("%s - error: invalid path: %s\n", __func__, path);
		return -EINVAL;
	}

	if (current_offset >= start_offset) {
		do_lookup(0, path, ".", &e);
		debug_output("%s - filler-ing '.', inum 0x%" PRIx64 "\n",
			__func__, e.attr.st_ino);

		if ((ret = filler(buf, ".", &e.attr, 0, FUSE_FILL_DIR_PLUS)))
			output("filler returned %d: %m\n", ret);
	}
	current_offset++;

	if (current_offset >= start_offset) {
		do_lookup(0, path, "..", &e);
		debug_output("%s - filler-ing '..', inum 0x%" PRIx64 "\n",
			__func__, e.attr.st_ino);

		if ((ret = filler(buf, "..", &e.attr, 0, FUSE_FILL_DIR_PLUS)))
			output("filler returned %d: %m\n", ret);
	}
	current_offset++;

	for (i = 0 ; i < FILE_COUNT ; i++) {
		char dirent_name[32];

		if (current_offset >= start_offset) {
			snprintf(dirent_name, sizeof(dirent_name) - 1, "file_%d", i);
			do_lookup(0, path, dirent_name, &e);
			debug_output("%s - filler-ing '%s', inum 0x%" PRIx64 "\n",
				__func__, dirent_name, e.attr.st_ino);

			if ((ret = filler(buf, dirent_name, &e.attr, 0, FUSE_FILL_DIR_PLUS)))
				output("filler returned %d: %m\n", ret);

		}
		current_offset++;
	}
	if (path_depth(path) < TREE_DEPTH - 1) {
		char dirent_name[32];

		for (i = 0 ; i < DIR_COUNT ; i++) {

			if (current_offset >= start_offset) {
				snprintf(dirent_name, sizeof(dirent_name) - 1, "dir_%d", i);
				do_lookup(0, path, dirent_name, &e);

				debug_output("%s - filler-ing '%s', inum 0x%" PRIx64 "\n",
					__func__, dirent_name, e.attr.st_ino);

				if ((ret = filler(buf, dirent_name, &e.attr, 0, FUSE_FILL_DIR_PLUS)))
					output("filler returned %d: %m\n", ret);
			}
			current_offset++;
		}
	}

	return 0;
}
static int repro_opendir(const char *path, struct fuse_file_info *ffi) {
	uint64_t inum;

	if ((inum = get_path_inum(path)) == INVALID_PATH) {
		output("%s - error: invalid path: %s\n", __func__, path);
		return -EINVAL;
	}

	debug_output("%s - path: %s - inum: 0x%" PRIx64 "\n", __func__, path, inum);

	ffi->fh = inum;

	return 0;
}
static int repro_read(void *req_buf, const char *path, size_t size, off_t off, bool lowlevel) {
	char contents[128];
	int len, copied;

	snprintf(contents, sizeof(contents), "contents of '%s'\n", path);
	len = strlen(contents);

	if (off > len)
		copied = 0;
	else
		copied = len - off;

	if (copied > size)
		copied = size;

	if (lowlevel) {
		fuse_req_t req = (fuse_req_t)req_buf;
		if (copied)
			fuse_reply_buf(req, contents + off, copied);
		else
			fuse_reply_buf(req, NULL, 0);
	} else
		memcpy(req_buf, contents + off, copied);
	return copied;
}
static void repro_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *ffi) {
	char *path;

	path = inum_to_path(ino);

	repro_read(req, path, size, off, true);
	free_mem(path);
}
static int repro_hl_read(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *ffi) {
	uint64_t inum;

	if ((inum = get_path_inum(path)) == INVALID_PATH) {
		output("%s - error: invalid path: %s\n", __func__, path);
		return -EINVAL;
	}

	return repro_read(buf, path, size, off, false);
}
static const struct fuse_lowlevel_ops repro_ll_ops = {
	.init		= repro_ll_init,
	.lookup		= repro_ll_lookup,
	.getattr	= repro_ll_getattr,
	.readdir	= repro_ll_readdir,
	.readdirplus	= repro_ll_readdir_plus,
	.opendir	= repro_ll_opendir,
	.open		= repro_ll_open,
	.read		= repro_ll_read,
	.statfs		= repro_ll_statfs,
	.releasedir	= repro_ll_releasedir,
};
static const struct fuse_operations repro_ops = {
//	.init		= repro_init,
	.getattr	= repro_getattr,
	.readdir	= repro_readdir,
//	.opendir	= repro_opendir,
//	.open		= repro_open,
	.read		= repro_hl_read,
	.statfs		= repro_hl_statfs,
//	.releasedir	= repro_releasedir,
};

static const struct fuse_opt repro_config_opts[] = {
	REPRO_FS_OPT("--lowlevel",		api, lowlevel),
	REPRO_FS_OPT("--highlevel",		api, highlevel),
	REPRO_FS_OPT("--dir_count=%lu",		dir_count, 0),
	REPRO_FS_OPT("--file_count=%lu",	file_count, 0),
	REPRO_FS_OPT("--depth=%d",		desired_depth, 0),
	FUSE_OPT_END
};

int main(int argc, char *argv[]) {
	int ret = -1;

	memset(&repro_fs, 0, sizeof(repro_fs));

	repro_fs.exe = strdup(argv[0]);
	repro_fs.args = (struct fuse_args)FUSE_ARGS_INIT(argc, argv);

	repro_fs.api = highlevel;

	repro_fs.uid = getuid();
	repro_fs.gid = getgid();
	repro_fs.attr_timeout = REPRO_FS_ATTR_TIMEOUT;
	repro_fs.entry_timeout = REPRO_FS_ENTRY_TIMEOUT;

	repro_fs.dir_count = 64;
	repro_fs.file_count = 128;
	repro_fs.desired_depth = 15;

	if ((fuse_opt_parse(&repro_fs.args, &repro_fs, repro_config_opts, NULL)) < 0) {
		output("error parsing\n");
		return EXIT_FAILURE;
	}

	output("with %d dirs, %d files, bits/dir = %d, desired depth %d, depth %d, depth_bits %d, MAX_POSSIBLE_DEPTH %d\n",
		(int)DIR_COUNT, (int)FILE_COUNT, (int)BITS_PER_LEVEL, (int)DESIRED_TREE_DEPTH, (int)TREE_DEPTH, (int)DEPTH_BITS, (int)MAX_POSSIBLE_DEPTH);
	calc_inodes();

	if (repro_fs.api == lowlevel) {
		output("using lowlevel api\n");
		// singlethread, foreground, debug, nodefault_subtype, *mountpoint, show_version, show_help, clone_fd, max_idle_threads
		if ((fuse_parse_cmdline(&repro_fs.args, &repro_fs.cmdline_opts)) < 0) {
			output("error parsing\n");
			return EXIT_FAILURE;
		}
		repro_fs.ll_ops = repro_ll_ops;

		ret = repro_fuse_main_ll(repro_fs.args.argc, repro_fs.args.argv);
	} else {
		output("using highlevel api\n");

		repro_fs.ops = repro_ops;
		ret = fuse_main(repro_fs.args.argc, repro_fs.args.argv, &repro_fs.ops, NULL);
	}

	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
