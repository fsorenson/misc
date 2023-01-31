/*
	Frank Sorenson <sorenson@redhat.com>, 2021

	Resolve a path, one element at a time, allowing
	debugging of spaghetti symlinks or determination
	of all intermediate paths visited.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/fsuid.h>
#include <sys/sysmacros.h>

#ifdef STATX_TYPE
#define HAVE_STATX 1
#else
#define HAVE_STATX 0
#endif

struct config_struct {
	int verbosity;
	bool have_statx_syscall;
	bool show_steps;
} config = {
	.verbosity = 0,
	.have_statx_syscall = false,
	.show_steps = true,
};

#define MAX_PATH_COUNT 100

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)
#define debug_output(lvl, fmt, ...) do { \
	if (config.verbosity >= lvl) \
		output("%s - " fmt, __func__, ##__VA_ARGS__); \
} while (0)

#define err_exit(ret, msg...) do { \
	output(msg); \
	exit(ret); \
} while (0)

#define free_mem(ptr) do { \
	if (ptr) \
		free(ptr); \
	ptr = NULL; \
} while (0)

void dedup_slashes(char **old_path) {
	int len = strlen(*old_path), new_len = 0;
	int i;
	unsigned char last_ch = '\0';
	char *new_path = NULL;

	debug_output(2, "\n - dedup_slashes(\n'%s'\n, length: %d)\n", *old_path, len);

	if (len == 0)
		goto out;

	new_path = strdup(*old_path);

	for (i = 0 ; i < len + 1 ; i++) {
		unsigned char this_ch = (*old_path)[i];

		if (! (this_ch == '/' && last_ch == '/'))
			new_path[new_len++] = this_ch;
		last_ch = this_ch;
	}
	if (new_len > 0)
		new_len--;
	while (new_len > 1 && new_path[new_len - 1] == '/')
		new_path[--new_len] = '\0';

	if (new_len != len) {
		debug_output(1, "removed %d characters\n", len - new_len);
		output("'%s' => '%s'\n", *old_path, new_path);
		free_mem(*old_path);
		*old_path = strdup(new_path);
	}
out:
	debug_output(2, "new path: \n'%s'\n, new length: %d\n", *old_path, new_len);

	free_mem(new_path);
}

struct path_ele;
struct path_ele {
	struct path_ele *next;
	struct path_ele *prev;
	char name[];
} path_ele_t;

static inline void INIT_PATH_HEAD(struct path_ele *head) {
        head->next = head;
        head->prev = head;
}
struct path_ele *alloc_path_ele(int namelen) {
	struct path_ele *ele = malloc(sizeof(struct path_ele) + namelen);
	memset(ele, 0, sizeof(struct path_ele) + namelen);

	debug_output(2, "allocated %lu bytes at %p\n", sizeof(struct path_ele) + namelen, ele);

	return ele;
}
struct path_ele *new_ele(const char *name) {
	int len = strlen(name) + 1;
	struct path_ele *ele = alloc_path_ele(len);

	strcpy(ele->name, name);
	ele->next = ele->prev = ele;

	debug_output(2, "allocated %d bytes for new ele at %p - '%s'\n", len, ele, ele->name);

	return ele;
}
struct path_ele *alloc_path_head(void) {
	struct path_ele *head = alloc_path_ele(0);
	INIT_PATH_HEAD(head);
	debug_output(2, "allocated path head element %p\n", head);
	return head;
}
void free_ele(struct path_ele *ele) {
	debug_output(2, "free ele %p\n", ele);
	free_mem(ele);
}
static bool path_empty(const struct path_ele *head) {
        return head->next == head;
}

int path_len(struct path_ele *head) {
	struct path_ele *p;
	int i = 0;

	if (!head)
		err_exit(EXIT_FAILURE, "path is null\n");

	p = head->next;
	while (p != head) {
		i++;
		p = p->next;
	}
	return i;
}
void print_path(struct path_ele *head) {
	char path[4096];
	struct path_ele *p;
	int count = 0;

	if (!head)
		err_exit(EXIT_FAILURE, "path is null\n");

	memset(path, 0, sizeof(path));

	p = head->next;
	while (p != head) {
//		if (count++ > 0)
			strcat(path, "/");
		strcat(path, p->name);
		p = p->next;
	}
	output("%s", path);
}

static void path_insert(struct path_ele *new,
		 struct path_ele *prev,
		 struct path_ele *next) {
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}
static void path_add(struct path_ele *new, struct path_ele *head) {
	path_insert(new, head, head->next);
}
static void path_add_tail(struct path_ele *new, struct path_ele *head) {
	path_insert(new, head->prev, head);
}
static struct path_ele *path_pop_first(struct path_ele *head) {
	struct path_ele *ele = head->next;

	if (path_empty(head))
		return NULL;

	ele->next->prev = head;
	head->next = ele->next;
	ele->next = ele->prev = ele;

	return ele;
}
static struct path_ele *path_pop_last(struct path_ele *head) {
	if (path_empty(head))
		return NULL;

	struct path_ele *ele = head->prev;

	ele->prev->next = head;
	head->prev = ele->prev;
	ele->next = ele->prev = ele;

	return ele;
}
static void free_path_list(struct path_ele *head) {
	struct path_ele *ele = head->next;

	while (!path_empty(head)) {
		ele = path_pop_last(head);
		free_ele(ele);
	}
}

struct path_ele *string_to_path_list(char *path_str) {
	char *tmp1 = NULL, *tmp2 = NULL, *p;
	struct path_ele *head = NULL;
	struct path_ele *ele = NULL;

	head = alloc_path_head();

	debug_output(2, "path head %p for '%s'\n", head, path_str);

	tmp1 = strdup(path_str);
	dedup_slashes(&tmp1);
	p = tmp1;
	if (*p == '/')
		p++;
	while (*p) {
		char *slash = index(p, '/');

		if (slash) {
			tmp2 = strndup(p, slash - p);
			p += strlen(tmp2) + 1;
		} else {
			tmp2 = strdup(p);
			p += strlen(tmp2);
		}
		ele = new_ele(tmp2);
		path_add_tail(ele, head);
		free_mem(tmp2);
	}
	free_mem(tmp1);

	if (config.verbosity >= 2) {
		debug_output(2, "resulting path:\n");
		ele = head->next;
		while (ele != head) {
			debug_output(2, "    %p -> name (%p) '%s'\n",
				ele, ele->name, ele->name);
			ele = ele->next;
		}
	}
	return head;
}

#define MAX_LOOP_CHECKER_SIZE (32*16) /* 512 */
//#define MAX_LOOP_CHECK_COUNT	32
struct loop_checker_struct {
	uint32_t major;
	uint32_t minor;
	uint64_t ino;
};
#define LOOP_CHECKER_HDR \
	uint32_t count; \
	uint32_t max_count
struct loop_checker_hdr {
	LOOP_CHECKER_HDR;
};
struct loop_checker;
struct loop_checker {
	LOOP_CHECKER_HDR;

	struct loop_checker_struct links_visited[(MAX_LOOP_CHECKER_SIZE - sizeof(struct loop_checker_hdr)) / sizeof(struct loop_checker_struct)];
};
#define MAX_LOOP_CHECK_COUNT ((MAX_LOOP_CHECKER_SIZE - sizeof(struct loop_checker_hdr)) / sizeof(struct loop_checker_struct))

//static struct loop_checker *loop_checker = NULL;
static struct loop_checker loop_checker;
void init_loop_checker(void) {

	memset(&loop_checker, 0, sizeof(struct loop_checker));
	loop_checker.max_count = MAX_LOOP_CHECK_COUNT;
}
void reset_loop_checker(void) {
	init_loop_checker();
}
/*
	1/true - is a loop
	0/false - not a loop
	-1 - not a loop, but hit max count
*/
int symlink_is_loop(struct loop_checker_struct *checkee) {
	int i;

	debug_output(2, "checking whether major: %d  minor: %d  ino: %ld is a loop\n", checkee->major, checkee->minor, checkee->ino);

	for (i = 0 ; i < loop_checker.count ; i++) {
		if (! memcmp(&loop_checker.links_visited[i], checkee, sizeof(struct loop_checker_struct)))
			return true;
	}
	if (loop_checker.count >= loop_checker.max_count)
		return -1;
	memcpy(&loop_checker.links_visited[loop_checker.count++], checkee, sizeof(struct loop_checker_struct));
	return false;
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
char *make_mode_string(char *buf, int mode) {
	buf[0] = mode_type_char(mode);
	mode_bits_string(buf + 1, mode);
	return buf;
}
#if 0
struct fsid_types {
	unsigned long fsid;
	const char *name;
};
const struct fsid_types fsid_types[] = {
	{ 0x5a3c69f0, "aafs" },
	{ 0xadf5, "adfs" },
	{ 0xadff, "affs" },
	{ 0x5346414F, "afs" },
	{ 0x6B414653, "afs" },
	{ 0x09041934, "anon_indoe" },
	{ 0x0187, "autofs" },
	{ 0x13661366, "balloon_kvm" },
	{ 0x62646576, "bdevfs" },
	{ 0xcafe4a11, "bff_fs" },
	{ 0x6c6f6f70, "binderfs" },
	{ 0x42494e4d, "bin_fmt" },
	{ 0x73727279, "btrfs" },
	{ 0x9123683E, "btrfs" },
	{ 0x63677270, "cgroup2" },
	{ 0x27e0eb, "cgroup" },
	{ 0x73757245, "coda" },
	{ 0x28cd3d45, "cramfs" },
	{ 0x453dcd28, "cramfs_wend" },
	{ 0x64646178, "daxfs" },
	{ 0x64626720, "debugfs" },
	{ 0x454d444d, "devmem" },
	{ 0x1cd1, "devpts" },
	{ 0x444d4142, "dma_buf" },
	{ 0xf15f, "ecryptfs" },
	{ 0xde5e81e4, "efivars" },
	{ 0x414A53, "efs" },
	{ 0xE0F5E1E2, "erofs" },
	{ 0xEF53, "ext*" },
	{ 0xF2F52010, "f2fs" },
	{ 0xBAD1DEA, "futexfs" },
	{ 0x00c0ffee, "hostfs" },
	{ 0xf995e849, "hpfs" },
	{ 0x958458f6, "hugetlbfs" },
	{ 0x9660, "isofs" },
	{ 0x72b6, "jffs" },
	{ 0x2468, "minix2" },
	{ 0x2478, "minix2" },
	{ 0x4d5a, "minix3" },
	{ 0x137F, "minix" },
	{ 0x2478, "minix2" },
	{ 0x4d5a, "minix3" },
	{ 0x137F, "minix" },
	{ 0x138F, "minix" },
	{ 0x4d44, "msdos" },
	{ 0x11307854, "mtd_inode" },
	{ 0x564c, "ncp" },
	{ 0x6969, "nfs" },
	{ 0x3434, "nilfs" },
	{ 0x6e736673, "nsfs" },
	{ 0x7461636f, "ocfs2" },
	{ 0x9fa1, "openprom" },
	{ 0x794c7630, "overlay" },
	{ 0x50495045, "pipefs" },
	{ 0xc7571590, "ppc_cmm" },
	{ 0x9fa0, "proc" },
	{ 0x6165676C, "pstorefs" },
	{ 0x002f, "qnx4" },
	{ 0x68191122, "qnx6" },
	{ 0x858458f6, "ramfs" },
	{ 0x7655821, "rdtgroup" },
	{ 0x73636673, "securityfs" },
	{ 0x52650e4973450e72, "reiserfs" }, /* actually longer, but can't differentiate in 8 bytes */
	{ 0xf97cff8c, "selinux" },
	{ 0x43415d53, "smack" },
	{ 0x517B, "smb" },
	{ 0x534F434B, "sockfs" },
	{ 0x73717368, "squashfs" },
	{ 0x57AC6E9D, "stackend" },
	{ 0x62656572, "sysfs" },
	{ 0x01021994, "tmpfs" },
	{ 0x74726163, "tracefs" },
	{ 0x15013346, "udf" },
	{ 0x9fa2, "usrdevice" },
	{ 0x01021997, "v9fs" },
	{ 0xabba1974, "xenfs" },
	{ 0x58465342, "xfs" },
	{ 0x33, "z3fold" },
	{ 0x5a4f4653, "zonefs" },
	{ 0x58295829, "zsmalloc" },
};
#endif
char *fstype(unsigned long fsid) {
	switch (fsid) {
		case 0x5a3c69f0: return "aafs"; break;
		case 0xadf5: return "adfs"; break;
		case 0xadff: return "affs"; break;
		case 0x5346414F: return "afs"; break;
		case 0x6B414653: return "afs"; break;
		case 0x09041934: return "anon_indoe"; break;
		case 0x0187: return "autofs"; break;
		case 0x13661366: return "balloon_kvm"; break;
		case 0x62646576: return "bdevfs"; break;
		case 0xcafe4a11: return "bff_fs"; break;
		case 0x6c6f6f70: return "binderfs"; break;
		case 0x42494e4d: return "bin_fmt"; break;
		case 0x73727279: return "btrfs"; break;
		case 0x9123683E: return "btrfs"; break;
		case 0x63677270: return "cgroup2"; break;
		case 0x27e0eb: return "cgroup"; break;
		case 0x73757245: return "coda"; break;
		case 0x28cd3d45: return "cramfs"; break;
		case 0x453dcd28: return "cramfs_wend"; break;
		case 0x64646178: return "daxfs"; break;
		case 0x64626720: return "debugfs"; break;
		case 0x454d444d: return "devmem"; break;
		case 0x1cd1: return "devpts"; break;
		case 0x444d4142: return "dma_buf"; break;
		case 0xf15f: return "ecryptfs"; break;
		case 0xde5e81e4: return "efivars"; break;
		case 0x414A53: return "efs"; break;
		case 0xE0F5E1E2: return "erofs"; break;
		case 0xEF53: return "ext*"; break;
		case 0xF2F52010: return "f2fs"; break;
		case 0xBAD1DEA: return "futexfs"; break;
		case 0x00c0ffee: return "hostfs"; break;
		case 0xf995e849: return "hpfs"; break;
		case 0x958458f6: return "hugetlbfs"; break;
		case 0x9660: return "isofs"; break;
		case 0x72b6: return "jffs"; break;
		case 0x2468: return "minix2"; break;
		case 0x2478: return "minix2"; break;
		case 0x4d5a: return "minix3"; break;
		case 0x137F: return "minix"; break;
		case 0x138F: return "minix"; break;
		case 0x4d44: return "msdos"; break;
		case 0x11307854: return "mtd_inode"; break;
		case 0x564c: return "ncp"; break;
		case 0x6969: return "nfs"; break;
		case 0x3434: return "nilfs"; break;
		case 0x6e736673: return "nsfs"; break;
		case 0x7461636f: return "ocfs2"; break;
		case 0x9fa1: return "openprom"; break;
		case 0x794c7630: return "overlay"; break;
		case 0x50495045: return "pipefs"; break;
		case 0xc7571590: return "ppc_cmm"; break;
		case 0x9fa0: return "proc"; break;
		case 0x6165676C: return "pstorefs"; break;
		case 0x002f: return "qnx4"; break;
		case 0x68191122: return "qnx6"; break;
		case 0x858458f6: return "ramfs"; break;
		case 0x7655821: return "rdtgroup"; break;
		case 0x52650e4973450e72: return "reiserfs"; break;  /* actually longer, but can't differentiate in 8 bytes */
		case 0x73636673: return "securityfs"; break;
		case 0xf97cff8c: return "selinux"; break;
		case 0x43415d53: return "smack"; break;
		case 0x517B: return "smb"; break;
		case 0x534F434B: return "sockfs"; break;
		case 0x73717368: return "squashfs"; break;
		case 0x57AC6E9D: return "stackend"; break;
		case 0x62656572: return "sysfs"; break;
		case 0x01021994: return "tmpfs"; break;
		case 0x74726163: return "tracefs"; break;
		case 0x15013346: return "udf"; break;
		case 0x9fa2: return "usrdevice"; break;
		case 0x01021997: return "v9fs"; break;
		case 0xabba1974: return "xenfs"; break;
		case 0x58465342: return "xfs"; break;
		case 0x33: return "z3fold"; break;
		case 0x5a4f4653: return "zonefs"; break;
		case 0x58295829: return "zsmalloc"; break;

		default: return "???"; break;
	};
}

struct stat_info_struct {
	uint64_t size;
	uint64_t ino;
	uint64_t mount_id;
	uint32_t major;
	uint32_t minor;
	uid_t uid;
	gid_t gid;
	int mode;
	bool stat_error;
	bool have_mount_id;
};
struct stat_info_struct get_stat_info(int dfd, const char *pathname) {
	struct stat_info_struct stat_info;
	memset(&stat_info, 0, sizeof(struct stat_info_struct));

#if HAVE_STATX
	if (config.have_statx_syscall) {
		struct statx stx;
		if ((statx(dfd, pathname, AT_SYMLINK_NOFOLLOW | (pathname[0] == '\0' ? AT_EMPTY_PATH : 0), STATX_ALL, &stx)) < 0) {
			stat_info.stat_error = true;
			goto out;
		}

		stat_info.uid = stx.stx_uid;
		stat_info.gid = stx.stx_gid;
		stat_info.mode = stx.stx_mode;
		stat_info.ino = stx.stx_ino;
		stat_info.size = stx.stx_size;
		stat_info.major = stx.stx_dev_major;
		stat_info.minor = stx.stx_dev_minor;
#ifdef STATX_MNT_ID
		if (stx.stx_mask & STATX_MNT_ID) {
			stat_info.have_mount_id = true;
			stat_info.mount_id = stx.stx_mnt_id;
		}
#endif /* STATX_MNT_ID */
	} else {
#else
	{
#endif
		struct stat st;
		if ((fstatat(dfd, pathname, &st, AT_SYMLINK_NOFOLLOW | (pathname[0] == '\0' ? AT_EMPTY_PATH : 0))) < 0) {
			stat_info.stat_error = true;
			goto out;
		}

		stat_info.size = st.st_size;
		stat_info.uid = st.st_uid;
		stat_info.gid = st.st_gid;
		stat_info.mode = st.st_mode;
		stat_info.ino = st.st_ino;
		stat_info.major = major(st.st_dev);
		stat_info.minor = minor(st.st_dev);
	}

out:
	return stat_info;
}

struct stat_info_struct show_stat_info(int fd, struct path_ele *current_path, char *this_name, struct path_ele *remaining_path) {
//	bool have_mount_id = false;
	char mode_string[11];
	struct statfs stfs;
	struct stat_info_struct stat_info;

	stat_info = get_stat_info(fd, "");
	if (stat_info.stat_error)
		goto out;

	fstatfs(fd, &stfs);

	output("%6s %s ", fstype(stfs.f_type), make_mode_string(mode_string, stat_info.mode));

	output("uid: %d  gid: %d ", stat_info.uid, stat_info.gid);
	output(" maj: %d  min: %d ", stat_info.major, stat_info.minor);
	if (stat_info.have_mount_id)
		output(" mount_id: %ld ", stat_info.mount_id);

	output(" inode: %ld ", stat_info.ino);
	print_path(current_path);

	if (this_name)
		output("/%s ", this_name);

	if (remaining_path && !path_empty(remaining_path)) {
		output(" (remaining path to resolve: ");
		print_path(remaining_path);
		output(") ");
	}
out:
	return stat_info;
}

void follow_path(char *path_str) {
	struct path_ele *current_path, *remaining_path, *tmp_list, *this_ele;
	struct stat_info_struct stat_info;
	int path_count = 0;
	int dfd, fd;

	current_path = alloc_path_head();
	remaining_path = string_to_path_list(path_str);

open_root:
	dfd = open("/", O_RDONLY|O_PATH|O_DIRECTORY);
	show_stat_info(dfd, current_path, "", remaining_path);
	output("\n");
	while (!path_empty(remaining_path)) {
		if (++path_count > MAX_PATH_COUNT) {
			output("ELOOP - too many path levels or symbolic links\n");
			goto out;
		}
		this_ele = path_pop_first(remaining_path);

		if ((fd = openat(dfd, this_ele->name, O_RDONLY|O_PATH|O_NOFOLLOW)) < 0) {

			output("%6s %s ", "", "??????????");
			print_path(current_path);
			output("/%s ", this_ele->name);
			output("- error opening: %m\n");
			goto out;
		}


		stat_info = show_stat_info(fd, current_path, this_ele->name, remaining_path);
		output("\n");
		if (stat_info.stat_error) {
			output("error checking '");
			print_path(current_path);
			output("%s': %m\n", this_ele->name);
			goto out;
		}

		if (!strcmp(this_ele->name, ".")) {
			free_ele(this_ele);
			close(fd);
			continue;
		}
		if (!strcmp(this_ele->name, "..")) {
			struct path_ele *tmp_ele = NULL;
			close(dfd);
			dfd = fd;
			if (!path_empty(current_path))
				tmp_ele = path_pop_last(current_path);
			if (tmp_ele)
				free_ele(tmp_ele);
			free_ele(this_ele);
			continue;
		}

		switch (stat_info.mode & S_IFMT) {
			case S_IFDIR: {
				int new_dfd;

				if ((new_dfd = openat(dfd, this_ele->name, O_RDONLY|O_PATH)) < 0) {
					output("could not open ");
					print_path(current_path);
					output("/%s: %m\n", this_ele->name);
					goto out;
				}
				close(dfd);
				dfd = new_dfd;
				path_add_tail(this_ele, current_path);

			} ; break;
			case S_IFLNK: {
				struct loop_checker_struct lcs;
				char *link = NULL;
				int is_loop, ret;


				lcs = (struct loop_checker_struct) {
					.major = stat_info.major,
					.minor = stat_info.minor,
					.ino = stat_info.ino
				};

				link = malloc(stat_info.size + 1);

				if ((ret = readlinkat(dfd, this_ele->name, link, stat_info.size + 1)) < 0) {
//					if (strlen(ret == 0))
//					err_exit(EXIT_FAILURE, "Invalid link");
					goto out_invalid_link;
				}
				link[ret] = '\0';

				output("               => '%s'\n", link);

				if ((is_loop = symlink_is_loop(&lcs)) < 0) {
					output("ELOOP - Too many levels of symbolic links\n");
					goto out;
				}
				if (is_loop) {
					output("ELOOP - already visited this symlink\n");
					goto out;
				}

				dedup_slashes(&link);

				if (link[0] == '/') {
					free_path_list(current_path);
					close(dfd);
					dfd = open("/", O_RDONLY|O_PATH|O_DIRECTORY);
				} else if (!strcmp(link, this_ele->name)) {
					free_mem(link);
					output("ELOOP - symlink loops back to itself\n");
					goto out;
				}
				tmp_list = string_to_path_list(link);
				while (!path_empty(tmp_list))
					path_add(path_pop_last(tmp_list), remaining_path);
				free_ele(tmp_list);

				free_mem(link);
				if (path_empty(current_path))
					goto open_root;
			} break;

			/* should be done */
			case S_IFREG:
			case S_IFBLK:
			case S_IFCHR:
			case S_IFIFO:
			case S_IFSOCK: {
				path_append(this_ele, current_path);

				if (!path_empty(remaining_path)) {
					output("  cannot follow down ");
					print_path(current_path);
					output(" (length: %d)  --  not a directory\n", path_len(current_path));
					output("remaininig path: ");
					print_path(remaining_path);
					output(" (length: %d)", path_len(remaining_path));
					output("\n");
				} else {
//					output("complete\n");
				}
				goto out;
			} break;

			default:
				output("bah\n");
				break;
		}
	}

out:
	free_path_list(current_path);
	free_ele(current_path);

	free_path_list(remaining_path);
	free_ele(remaining_path);

	if (this_ele)
		free_ele(this_ele);
	return;

out_invalid_link:
	output("  invalid link ");
	print_path(current_path);
	output("%s  <- %m\n", this_ele->name);
	output("remaininig path: ");
	print_path(remaining_path);
	output("\n");
	goto out;

out_not_dir:
	output("  cannot follow down ");
	print_path(current_path);
	output("%s  <- not a directory\n", this_ele->name);
	output("remaininig path: ");
	print_path(remaining_path);
	output("\n");
	goto out;
}

void check_component(int dfd, char *parent_path, char *this_path_ele, char *remaining_path) {
	struct stat st;
	char *current_path = NULL;
	char *next_path_ele = NULL;
	char *next_path_remaining = NULL;
	char *slash = NULL;

	output("\n");
	output("parent path: '%s'; this_path_ele: '%s'; remaining path: '%s'\n",
		parent_path, this_path_ele, remaining_path);



	if (strlen(parent_path) && parent_path[strlen(parent_path) - 1] == '/')
		asprintf(&current_path, "%s%s", parent_path, this_path_ele);
	else if (strlen(parent_path))
		asprintf(&current_path, "%s/%s", parent_path, this_path_ele);
	else
		current_path = strdup("/");


	output("    current path: %s\n", current_path);
	slash = index(remaining_path, '/');
	if (slash) {
		next_path_ele = strndup(remaining_path, slash - remaining_path);
		while (*slash == '/')
			slash++;
		next_path_remaining = strdup(slash);
		output("found slash at index %ld of '%s' (next path '%s', next path remaining '%s')\n", slash - remaining_path, remaining_path, next_path_ele, next_path_remaining);
	} else {
		next_path_ele = strdup(remaining_path);
		next_path_remaining = strdup("");
		output("no slash found in '%s' (next path '%s', next path remaining '%s')\n", remaining_path, next_path_ele, next_path_remaining);
	}


	output("%s", current_path);

	if (fstatat(dfd, this_path_ele, &st, AT_SYMLINK_NOFOLLOW) < 0) {
		output(" does not exist: %m (%d)\n", errno);
		goto out;
	}

	switch (st.st_mode & S_IFMT) {
		case S_IFBLK:
		case S_IFCHR:
		case S_IFIFO:
		case S_IFSOCK:
			if (strlen(remaining_path)) {
				output("  cannot follow down %s/%s - ENOTDIR\n", current_path, remaining_path);
				goto out;
			}
			break;
		case S_IFDIR: {
			int new_dfd;

			output("  directory\n");

			if (remaining_path[0] == '\0')
				goto out;

			remaining_path += strlen(next_path_ele) + 1;
			while (*remaining_path == '/')
				remaining_path++;

			if ((new_dfd = openat(dfd, this_path_ele, O_RDONLY|O_DIRECTORY)) < 0) {
				output("could not open %s: %m\n", current_path);
				goto out;
			}
			check_component(new_dfd, current_path, next_path_ele, next_path_remaining);
			close(new_dfd);
		} ; break;
		case S_IFREG: { /* should be done */
			if (strlen(remaining_path)) {
				output("  cannot follow path -- '%s' is not a directory\n", current_path);
				goto out;
			}
			output("\n");
			break;
		} ; break;
		case S_IFLNK: {
			char *link = NULL;
			int link_len = st.st_size + 1, ret;
			if (link_len < 2)
				link_len = PATH_MAX;
			link = malloc(link_len);
			memset(link, 0, link_len);

			if ((ret = readlinkat(dfd, this_path_ele, link, link_len)) < 0) {
//				if (strlen(ret == 0))
				output("Invalid link");
			}

			link[st.st_size] = '\0';

output("read link for '%s', link len: %d\n", this_path_ele, link_len);

			output(" => '%s'\n", link);

			free_mem(link);
		} ; break;
		default:
			output("bah\n");
			break;
	}



//         switch (sb.st_mode & S_IFMT) {
//         case S_IFBLK:  output("block device\n");            break;
//         case S_IFCHR:  output("character device\n");        break;
//         case S_IFDIR:  output("directory\n");               break;
//         case S_IFIFO:  output("FIFO/pipe\n");               break;
//         case S_IFLNK:  output("symlink\n");                 break;
//         case S_IFREG:  output("regular file\n");            break;
//         case S_IFSOCK: output("socket\n");                  break;
//          default:       output("unknown?\n");                break;


out:
	if (current_path)
		free_mem(current_path);
}


void resolve_path(char *path) {
	char *start_path_str = NULL;
//	struct path_ele *start_path, *remaining_path, *tmp_path;

//	start_path = alloc_path_head();
//	remaining_path = alloc_path_head();







//	output("path[0]: '%c'\n", path[0]);
//	dedup_slashes(&path);

	if (*path == '/') { /* absolute path */
		output("%s is an absolute path\n", path);
		start_path_str = strdup(path);
//		check_component(AT_FDCWD, "", "/", path);
	} else { /* relative path */
		char *cwd = get_current_dir_name();
		output("%s is a relative path\n", path);
		output("current directory: %s\n", cwd);

		asprintf(&start_path_str, "%s/%s", cwd, path);
	}

	output("resolving path %s\n", start_path_str);
	dedup_slashes(&start_path_str);

	follow_path(start_path_str);


#if 0

		start_path = get_current_dir_name();

		output("resolving path %s/%s\n", start_path, path);
		check_component(AT_FDCWD, start_path, start_path, path);

	}
#endif

//	check_component(AT_FDCWD, "", "/", "var/tmp/util-linux-2.36.2-1.fc34.src.rpm");

	free_mem(start_path_str);
}

#if HAVE_STATX
#include <sys/syscall.h>
void verify_statx_syscall(void) {
	struct statx stx;

	if ((syscall(SYS_statx, AT_FDCWD, "", AT_EMPTY_PATH|AT_NO_AUTOMOUNT, 0, &stx, NULL)) < 0)
		config.have_statx_syscall = false;
	else
		config.have_statx_syscall = true;
}
#else
#define verify_statx_syscall() do { } while (0)
#endif

int usage(const char *exe, int ret) {
	output("%s <path> [<path> ... ]\n", exe);
	return ret;
}

int main(int argc, char *argv[]) {
	int i;


	verify_statx_syscall();

	output("running with fsuid: %d, fsgid: %d\n", setfsuid(-1), setfsgid(-1));
	if (argc > 1) {
		for (i = 1 ; i < argc ; i++) {
			reset_loop_checker();
			resolve_path(argv[i]);
			if (i < argc)
				output("\n");
		}
	} else
		return usage(argv[0], EXIT_FAILURE);

	return EXIT_SUCCESS;
}
