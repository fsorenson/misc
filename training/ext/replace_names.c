#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <ext2fs/ext2fs.h>
#include <ext2fs/ext2_fs.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>

#define min(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a < b ? a : b; })
#define max(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a > b ? a : b; })

#define DEFAULT_UUID "1d9301b4-a0aa-4fee-9a89-3029748010c2"

/*
extern errcode_t ext2fs_dirhash2(int version, const char *name, int len,
                                 const struct ext2fs_nls_table *charset,
                                 int hash_flags,
                                 const __u32 *seed,
                                 ext2_dirhash_t *ret_hash,
                                 ext2_dirhash_t *ret_minor_hash);
*/
//ext2fs_dirent_name_len

static char *filename_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-~";


#define BUF_SIZE 4096
#define MAX_REPLACEMENTS 256
struct replacement_filenames {
	uint32_t len;
	char *old_name;
	char *new_name;
} *replacements = NULL;
int replacement_count = 0;
const struct ext2fs_nls_table *encoding = NULL;
uint32_t hash_seed[4] = { 0, 0, 0, 0 };

int find_old_replacement(const char *old_name, uint32_t len) {
	int i;

	for (i = 0 ; i < replacement_count ; i++) {
//		if (replacements[i].len == len)
//			printf("checking whether string '%s' matches '%s'\n",
//				replacements[i].old_name, old_name);
//		else
//			printf("string length doesn't match\n");
		if (replacements[i].len == len && !strncmp(old_name, replacements[i].old_name, len))
			return i;
	}
	return -1;
}
int find_new_replacement(const char *new_name, uint32_t len) {
	int i;

	for (i = 0 ; i < replacement_count ; i++) {
//		if (replacements[i].len == len)
//			printf("checking whether string '%s' matches '%s'\n",
//				replacements[i].new_name, new_name);
//		else
//			printf("string length doesn't match\n");
		if (replacements[i].len == len && !strncmp(new_name, replacements[i].new_name, len))
			return i;
	}
	return -1;
}
int add_replacement(const char *old_name, const char *new_name, int len) {
	replacements[replacement_count].len = len;
	replacements[replacement_count].old_name = strndup(old_name, len);
	replacements[replacement_count].new_name = strndup(new_name, len);
	return replacement_count++;
}

void printf_hash(const char *name, int len) {
	ext2_dirhash_t hash, minor_hash;

	ext2fs_dirhash2(EXT2_HASH_HALF_MD4_UNSIGNED,
		name,
		len,
		encoding,
		0,
		hash_seed,
		&hash, &minor_hash);

	printf("0x%08x : %08x", hash, minor_hash);
}

char *gen_new_name(int len, uint32_t min_hash, uint32_t max_hash) {
	unsigned char filename_array[256];
	char filename_string[256];
	ext2_dirhash_t hash, minor_hash;
	int i;

	memset(filename_array, 0, sizeof(filename_array));

	while (42) {
		for (i = 0 ; i < len ; i++)
			filename_string[i] = filename_chars[filename_array[i]];
		filename_string[len] = '\0';

		ext2fs_dirhash2(EXT2_HASH_HALF_MD4_UNSIGNED,
			filename_string,
			len,
			encoding,
			0,
			hash_seed,
			&hash, &minor_hash);

		if (min_hash <= hash && hash <= max_hash) {
			// check unique
			if (find_new_replacement(filename_string, len) < 0)
				return strndup(filename_string, len);
		}
		/* increment the string */
		i = len - 1;
		while (i >= 0) {
			filename_array[i]++;
			if (filename_array[i] >= sizeof(filename_chars)) {
				filename_array[i] = 0;
				i--;
			} else
				break;
			if (i < 0) {
				printf("error: failed to locate any more strings in the range\n");
				return NULL;
			}
		}
	}

	return NULL;
}

//filename min_hash max_hash

static struct option long_opts[] = {
	{ "replace", no_argument, NULL, 'r' },
	{ "print", no_argument, NULL, 'p' },
	{ "zero", no_argument, NULL, 'z' },
	{ "uuid", required_argument, NULL, 'u' },
	{ NULL, 0, 0, 0 },
};

int usage(const char *exe, int ret) {
	printf("usage: %s [ -r | --replace ] [ -p | --print ] [ -z | --zero ] [ -u <UUID> | --uuid <UUID> ] <blocks.bin> <min_hash> <max_hash>\n", exe);
	printf("\t-r | --replace\n\t\treplace filenames\n");
	printf("\t-p | --print\n\t\tprint directory entries\n");
	printf("\t-z | --zero\n\t\tzero gaps\n");
	printf("\t-Z | --zero_inodes\n\t\tzero out entries with inode number 0\n");
	printf("\t-u <UUID> | --uuid <UUID>\n\t\tuse the provided UUID\n");
	return ret;
}

int main(int argc, char *argv[]) {
	uint32_t min_hash, max_hash;
	char *uuid = DEFAULT_UUID;
	char temp_str[256];
	int name_len;

	char *blockfile = NULL;
	size_t blocksize = 0;
	struct ext2_dir_entry *dirent;
	struct ext2_dir_entry_tail *dirent_tail;
	int pos = 0, last_pos = 0, dirent_tail_pos;
	int open_flags;
	char *buf = NULL, *ptr;
	int fd;

	bool replace_entries = false;
	bool print_entries = false;
	bool zero_gaps = false; /* zero gaps between entries */
	bool zero_zero_inodes = false; /* zero out entries with inode number 0 */
	int arg, i;

	while ((arg = getopt_long(argc, argv, "rpzZhu:", long_opts, NULL)) != EOF) {
		switch (arg) {
			case 'r': replace_entries = true; break;
			case 'p': print_entries = true; break;
			case 'z': zero_gaps = true; break;
			case 'Z': zero_zero_inodes = true; break;
			case 'u':
				  ptr = optarg ? optarg : argv[optind];
				  uuid = strdup(ptr);
				  break;
			case 'h': return usage(argv[0], EXIT_SUCCESS); break;
			default:
				return usage(argv[0], EXIT_FAILURE); break;
		}
	}

//	if (argc != 4) {
	if (argc != optind + 3) {
		return usage(argv[0], EXIT_FAILURE);
	}

	blockfile = argv[optind++];
	min_hash = strtol(argv[optind++], NULL, 16);
	max_hash = strtol(argv[optind++], NULL, 16);

	if (uuid_parse(uuid, (unsigned char *)hash_seed)) {
		printf("error parsing uuid '%s': %m\n", uuid);
		return EXIT_FAILURE;
	}

	if (replace_entries) {
		replacements = malloc(sizeof(struct replacement_filenames) * MAX_REPLACEMENTS);
		memset(replacements, 0, sizeof(struct replacement_filenames) * MAX_REPLACEMENTS);
	}

	buf = malloc(BUF_SIZE);

	if (replace_entries || zero_gaps)
		open_flags = O_RDWR;
	else
		open_flags = O_RDONLY;

	fd = open(blockfile, open_flags);
	blocksize = read(fd, buf, BUF_SIZE);
	dirent_tail_pos = blocksize - sizeof(struct ext2_dir_entry_tail);
	dirent_tail = (struct ext2_dir_entry_tail *)(buf + dirent_tail_pos);

	while (pos < blocksize) {
//	while (pos < blocksize - sizeof(struct ext2_dir_entry_tail)) {
		int gap_size, gap_offset, rec_len;
		char *new_name;
		int ret;

		dirent = (struct ext2_dir_entry *)(buf + pos);

		name_len = ext2fs_dirent_name_len(dirent);
		strncpy(temp_str, dirent->name, name_len);
		temp_str[name_len] = '\0';
		rec_len = dirent->rec_len;

		printf("pos: %d, len: %d, name_len: %d, name_pos: %lu - ", pos, rec_len, name_len, pos + offsetof(struct ext2_dir_entry, name));
		if (replace_entries && (!zero_zero_inodes && dirent->inode != 0)) {
			if ((ret = find_old_replacement(temp_str, name_len)) >= 0) {
				printf("\tduplicate of entry %d - new name '%s'\n", ret, replacements[ret].new_name);
				new_name = replacements[ret].new_name;

				memcpy(buf + pos + offsetof(struct ext2_dir_entry, name), replacements[ret].new_name, name_len);
			} else {
				new_name = gen_new_name(name_len, min_hash, max_hash);

				ret = add_replacement(temp_str, new_name, name_len);
				memcpy(dirent->name, replacements[ret].new_name, name_len);

			}
		}
		if (print_entries) {
			printf("inode %d, '%s'", dirent->inode, temp_str);
			if (replace_entries && !(zero_zero_inodes && dirent->inode != 0)) {
				printf("-> '%s' - ", new_name);
				printf_hash(new_name, name_len);
			}
			printf("\n");
		}

		if (zero_zero_inodes && dirent->inode == 0) {
			struct ext2_dir_entry *last_dirent = (struct ext2_dir_entry *)(buf + last_pos);
			printf("zeroing entry with zero inode; %d bytes at offset %d\n",
				rec_len, pos);

			memset(buf + pos, 0, rec_len);
			printf("increasing record length of entry at pos %d from %d to %d\n",
				last_pos, last_dirent->rec_len, last_dirent->rec_len + rec_len);
			last_dirent->rec_len += rec_len;
		} else if (zero_gaps) {
			gap_size = rec_len - name_len - offsetof(struct ext2_dir_entry, name);
			gap_offset = pos + offsetof(struct ext2_dir_entry, name) + name_len;

			// maybe this doesn't actually have a tail?
//			gap_size = min(gap_size, dirent_tail_pos - gap_offset);
			if (gap_size) {
				printf("will zero gap of %d bytes at offset %d\n", gap_size, gap_offset);
				memset(buf + gap_offset, 0, gap_size);
			}
		} else {
			gap_size = rec_len - name_len - offsetof(struct ext2_dir_entry, name);
			gap_offset = pos + offsetof(struct ext2_dir_entry, name) + name_len;

			if (gap_size)
				printf("would zero gap of %d bytes at offset %d\n", gap_size, gap_offset);
		}


		if (replace_entries || zero_gaps || zero_zero_inodes) {
			lseek(fd, 0, SEEK_SET);
			write(fd, buf, blocksize);
		}

		if (zero_zero_inodes && dirent->inode != 0)
			last_pos = pos;
		pos += rec_len;
	}
/*
	printf("tail entry - pos: %d, size: %ld, rec_len: %d, reserved_name_len: 0x%04x, checksum: 0x%08x\n",
		pos, sizeof(struct ext2_dir_entry_tail), dirent_tail->det_rec_len, dirent_tail->det_reserved_name_len, dirent_tail->det_checksum);
*/
	close(fd);

	if (buf)
		free(buf);
	if (replacements) {
		for (i = 0 ; i < replacement_count ; i++) {
			if (replacements[i].old_name)
				free(replacements[i].old_name);
			if (replacements[i].new_name)
				free(replacements[i].new_name);
		}
	}


	return EXIT_SUCCESS;
}
