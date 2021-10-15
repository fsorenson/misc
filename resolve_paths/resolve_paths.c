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
#include <limits.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/fsuid.h>

int verbosity = 0;

#define MAX_PATH_COUNT 100

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)
#define debug_output(lvl, args...) do { \
	if (verbosity >= lvl) \
		output(args); \
} while (0)

#define err_exit(ret, msg...) do { \
	output(msg); \
	exit(ret); \
} while (0)

void dedup_slashes(char **old_path) {
	int len = strlen(*old_path), new_len = 0;
	int i;
	unsigned char last_ch = '\0';
	char *new_path = NULL;

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
		free(*old_path);
		*old_path = strdup(new_path);
	}
out:
	if (new_path)
		free(new_path);
}

struct path_ele;

struct path_ele {
	char *name;
	struct path_ele *next;
	struct path_ele *prev;
} path_ele_t;

#define PATH_HEAD_INIT(name) { .next = &(name), .prev = &(name) }
#define PATH_HEAD(name) \
        struct path_ele name = PATH_HEAD_INIT(name)

static inline void INIT_PATH_HEAD(struct path_ele *head) {
        head->next = head;
        head->prev = head;
}
struct path_ele *alloc_path_ele(void) {
	struct path_ele *ele = malloc(sizeof(struct path_ele));
	memset(ele, 0, sizeof(struct path_ele));
	return ele;
}
struct path_ele *alloc_path_head(void) {
	struct path_ele *head = alloc_path_ele();
	INIT_PATH_HEAD(head);
	return head;
}
struct path_ele *new_ele(const char *name) {
	struct path_ele *ele = alloc_path_ele();

	ele->name = strdup(name);
	ele->next = ele->prev = ele;
	return ele;
}
void free_ele(struct path_ele *ele) {
	if (ele && ele->name)
		free(ele->name);
	if (ele)
		free(ele);
}
bool path_empty(const struct path_ele *head) {
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
	struct path_ele *p;

	if (!head)
		err_exit(EXIT_FAILURE, "path is null\n");

	p = head->next;
	while (p != head) {
		output("/%s", p->name);
		p = p->next;
	}
}

void __path_add(struct path_ele *new,
		struct path_ele *prev,
		struct path_ele *next) {
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}
void path_add(struct path_ele *new, struct path_ele *head) {
	__path_add(new, head, head->next);
}
void path_add_tail(struct path_ele *new, struct path_ele *head) {
	__path_add(new, head->prev, head);
}
void __path_del(struct path_ele *prev, struct path_ele *next) {
	next->prev = prev;
	prev->next = next;
}
struct path_ele *path_del(struct path_ele *ele) {
	__path_del(ele->prev, ele->next);
	ele->next = NULL;
	ele->prev = NULL;
	return ele;
}
struct path_ele *path_get_tail(struct path_ele *head) {
	return head->prev;
}
struct path_ele *path_pop_first(struct path_ele *head) {
	if (path_empty(head))
		return NULL;
	return path_del(head->next);
}
struct path_ele *path_del_last(struct path_ele *head) {
	return path_del(head->prev);
}
struct path_ele *path_pop_last(struct path_ele *head) {
	if (path_empty(head))
		return NULL;
	return path_del(head->prev);
}
void free_path_list(struct path_ele *head) {
	while (!path_empty(head))
		path_del_last(head);
}

//void path_append(struct path_ele *head, struct path_ele *ele) {
void path_append(struct path_ele *ele, struct path_ele *head) {
	path_add_tail(ele, head);
}

struct path_ele *string_to_path_list(char *path_str) {
	char *tmp1, *tmp2, *p;
	struct path_ele *head = NULL;
	struct path_ele *ele = NULL;

	head = alloc_path_head();

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
		free(tmp2);
		path_append(ele, head);
	}
	free(tmp1);
	return head;
}



void t_list(void) {
	char *start_string, *temp_name, *p;
	PATH_HEAD(head);
	struct path_ele *ele;

	start_string = strdup("//this/is////a/test/");

	output("start string: %s\n", start_string);

	dedup_slashes(&start_string);
	output("deduped: %s\n", start_string);

	p = start_string;
	if (*p == '/')
		p++;
	while (*p) {
		char *slash = index(p, '/');

output("p: %s\n", p);
output("slash: %s\n", slash);

		if (slash) {
			temp_name = strndup(p, slash - p);
			p += strlen(temp_name) + 1;
		} else {
			temp_name = strdup(p);
			p += strlen(temp_name);
		}
		output("component: %s\n", temp_name);

		ele = new_ele(temp_name);
		free(temp_name);
		path_append(ele, &head);

	}

	output("length of path: %d\n", path_len(&head));
	output("path: ");
	print_path(&head);
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

struct stat show_stat_info(int fd, struct path_ele *current_path, char *this_name, struct path_ele *remaining_path) {
	char mode_string[11];
	struct statfs stfs;
	struct stat st;

	fstatat(fd, "", &st, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW);
//		fstatvfs(fd, &stvfs);
	fstatfs(fd, &stfs);


	mode_string[0] = mode_type_char(st.st_mode);
	mode_bits_string(mode_string + 1, st.st_mode);
//		output("%6s %s ", fstype(stvfs.f_fsid), mode_string);
	output("%6s %s ", fstype(stfs.f_type), mode_string);

	output("uid: %d  gid: %d ", st.st_uid, st.st_gid);
	output("inode: %ld ", st.st_ino);

//	if (path_empty(current_path))
//		output("/");
	print_path(current_path);

	if (this_name)
		output("/%s ", this_name);

	if (remaining_path && !path_empty(remaining_path)) {
		output(" (remaining path to resolve: ");
		print_path(remaining_path);
		output(") ");
	}

//	output("\n");
	return st;
}

void follow_path(char *path_str) {
	struct path_ele *current_path, *remaining_path, *tmp_list, *this_ele;
//	char mode_string[11];
//	struct statvfs stvfs;
//	struct statfs stfs;
	struct stat st;
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
/*
		fstatat(dfd, "", &st, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW);
//		fstatvfs(fd, &stvfs);
		fstatfs(dfd, &stfs);

		mode_string[0] = mode_type_char(st.st_mode);
		mode_bits_string(mode_string + 1, st.st_mode);
//		output("%6s %s ", fstype(stvfs.f_fsid), mode_string);
		output("%6s %s ", fstype(stfs.f_type), mode_string);

		output("uid: %ld  gid: %ld ", st.st_uid, st.st_gid);

		print_path(current_path);
		output("\n");
//		output("/%s", this_ele->name);

*/
		this_ele = path_pop_first(remaining_path);

//		if (fstatat(dfd, this_ele->name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
		if ((fd = openat(dfd, this_ele->name, O_RDONLY|O_PATH|O_NOFOLLOW)) < 0) {

			output("%6s %s ", "", "??????????");
			print_path(current_path);
			output("/%s ", this_ele->name);
			output("- error opening: %m\n");
			goto out;
		}


		st = show_stat_info(fd, current_path, this_ele->name, remaining_path);
/*
		fstatat(fd, "", &st, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW);
//		fstatvfs(fd, &stvfs);
		fstatfs(fd, &stfs);


		mode_string[0] = mode_type_char(st.st_mode);
		mode_bits_string(mode_string + 1, st.st_mode);
//		output("%6s %s ", fstype(stvfs.f_fsid), mode_string);
		output("%6s %s ", fstype(stfs.f_type), mode_string);

		output("uid: %ld  gid: %ld ", st.st_uid, st.st_gid);



		print_path(current_path);
*/
//		output("/%s", this_ele->name);


		if (!strcmp(this_ele->name, ".")) {
			free_ele(this_ele);
			close(fd);
			continue;
		}
		if (!strcmp(this_ele->name, "..")) {
//			int tmp_dfd = openat(dfd, "..", O_RDONLY|O_PATH|O_DIRECTORY);
//			close(dfd);
//			dfd = tmp_dfd;
			close(dfd);
			dfd = fd;
			if (!path_empty(current_path))
				path_del_last(current_path);
			free_ele(this_ele);
			continue;
		}

		switch (st.st_mode & S_IFMT) {
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
				output("\n");
				path_append(this_ele, current_path);

			} ; break;
			case S_IFLNK: {
				char *link = NULL;
				int link_len = st.st_size + 1, ret;

				if (link_len < 2)
					link_len = PATH_MAX;
				link = malloc(link_len);

				if ((ret = readlinkat(dfd, this_ele->name, link, link_len)) < 0) {
//					if (strlen(ret == 0))
//					err_exit(EXIT_FAILURE, "Invalid link");
					goto out_invalid_link;
				}

				output(" => '%s'\n", link);

				dedup_slashes(&link);
//output("after deduped slashes: %s", link);

				if (link[0] == '/') {
					free_path_list(current_path);
					close(dfd);
					dfd = open("/", O_RDONLY|O_PATH|O_DIRECTORY);
				} else if (!strcmp(link, this_ele->name)) {
					free(link);
					output("ELOOP - symlink loops back to itself\n");
					goto out;
				}
				tmp_list = string_to_path_list(link);
				while (!path_empty(tmp_list))
					path_add(path_pop_last(tmp_list), remaining_path);
				free_ele(tmp_list);

				free(link);
/*
output("new current_path: ");
print_path(current_path);
output("\nnew remaining_path: ");
print_path(remaining_path);
output("\n");
*/
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



#if 0
	if (!strcmp(this_path_ele, ".")) {
#		check_component(dfd, 
		goto out;
                        check_component(new_dfd, current_path, next_path_ele, next_path_remaining);


#endif

	if (fstatat(dfd, this_path_ele, &st, AT_SYMLINK_NOFOLLOW) < 0) {
//		if (errno == E
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

			if ((ret = readlinkat(dfd, this_path_ele, link, link_len)) < 0) {
//				if (strlen(ret == 0))
				output("Invalid link");
			}


			output(" => '%s'\n", link);


//			output("link size: %d\n", st.st_size);
//			      output("bah\n");


			free(link);
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
		free(current_path);
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

	if (start_path_str)
		free(start_path_str);
}

#define test_dedup(s) do { \
	char *tmp1, *tmp2; \
	tmp1 = strdup(s); \
	tmp2 = strdup(tmp1); \
	dedup_slashes(&tmp2); \
	printf("%s dedups to %s\n", tmp1, tmp2); \
	free(tmp1); \
	free(tmp2); \
} while (0)

int main(int argc, char *argv[]) {
	int i;

	output("running with fsuid: %d, fsgid: %d\n", setfsuid(-1), setfsgid(-1));
	if (argc > 1) {
		for (i = 1 ; i < argc ; i++) {
			resolve_path(argv[i]);
			if (i < argc)
				output("\n");
		}
	} else {
//		int dfd = open("/", O_RDONLY|O_DIRECTORY);

//		check_component(dfd, "/", "var", "tmp/util-linux-2.36.2-1.fc34.src.rpm");

//		check_component(AT_FDCWD, "", "/", "var/tmp/util-linux-2.36.2-1.fc34.src.rpm");
//		check_component(AT_FDCWD, "", "/", "var/tmp/util-linux-2.36.2-1.fc34.src.rpm");
//		check_component(AT_FDCWD, "", "/", "var/tmp/util-linux-2.36.2-1.fc34.src.rpm");
//		resolve_path("/var/tmp/util-linux-2.36.2-1.fc34.src.rpm");
	resolve_path("foo");
//		resolve_path("foo/bar");

//void check_component(int dfd, char *parent_path, char *this_path_ele, char *remaining_path) {
	}

	return EXIT_SUCCESS;
}
