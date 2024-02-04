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
#include <locale.h>
#include <errno.h>

#define min(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a < b ? a : b; })
#define max(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a > b ? a : b; })

#define likely(x)	__builtin_expect((x),1)
#define unlikely(x)	__builtin_expect((x),0)

#define DEFAULT_UUID "09567860-3a0d-46ef-960d-d582c7c80c8f"

/*
extern errcode_t ext2fs_dirhash2(int version, const char *name, int len,
                                 const struct ext2fs_nls_table *charset,
                                 int hash_flags,
                                 const __u32 *seed,
                                 ext2_dirhash_t *ret_hash,
                                 ext2_dirhash_t *ret_minor_hash);
*/
//ext2fs_dirent_name_len

#define FILENAME_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-~"
static char *filename_chars = FILENAME_CHARS;

const struct ext2fs_nls_table *encoding = NULL;
uint32_t hash_seed[4] = { 0, 0, 0, 0 };

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

unsigned char filename_array[256];
char filename_string[256];
int count_to_generate = 100;
unsigned long count = 0;

int incr_filename_array(int len) {
	static int hit_end = 0;
	int i = len - 1;

	if (hit_end)
		return 0;

	while (i >= 0) {
		filename_array[i]++;
		if (unlikely(filename_array[i] >= sizeof(FILENAME_CHARS) - 1)) {
			filename_array[i] = 0;
			i--;
		} else
			break;
		if (unlikely(i < 0)) {
			printf("error: failed to locate any more strings in the range\n");
			hit_end = 1;
			return 0;
		}
	}

	return 1;
}

char *gen_new_name(int len, uint32_t min_hash, uint32_t max_hash) {
	ext2_dirhash_t hash, minor_hash;
	int i;
	char *ret = NULL;

	while (42) {
		count++;
		if (unlikely(count % 100000 == 0)) {
			printf("count: %'lu\r", count);
			fflush(stdout);
		}

		for (i = 0 ; i < len ; i++)
			filename_string[i] = filename_chars[filename_array[i]];
		filename_string[len] = '\0';

//printf("trying %s\n", filename_string);
		ext2fs_dirhash2(EXT2_HASH_HALF_MD4_UNSIGNED,
			filename_string,
			len,
			encoding,
			0,
			hash_seed,
			&hash, &minor_hash);

		if (min_hash <= hash && hash <= max_hash) {
			ret = strndup(filename_string, len);
			incr_filename_array(len);
			goto out;
		}
		/* increment the string */
		if (incr_filename_array(len) == 0) {
			ret = NULL;
			goto out;
		}
	}

out:

	return ret;
}

//filename min_hash max_hash

static struct option long_opts[] = {
	{ "count", required_argument, NULL, 'c' },
	{ "create-dirs", required_argument, NULL, 'd' },
	{ "dirs", required_argument, NULL, 'd' },
	{ "skip", required_argument, NULL, 's' },
	{ "uuid", required_argument, NULL, 'u' },
	{ NULL, 0, 0, 0 },
};

int usage(const char *exe, int ret) {
	printf("usage: %s [ -c <count> | --count <count> ] [ -d | --dirs | --create-dirs ] [ -u <UUID> | --uuid <UUID> ] <len> <min_hash> <max_hash>\n", exe);
	printf("\t-u <UUID> | --uuid <UUID>\n\t\tuse the provided UUID\n");
	return ret;
}

int main(int argc, char *argv[]) {
	uint32_t min_hash, max_hash;
	char *uuid = DEFAULT_UUID;
	int name_len;
	bool create_dirs = false;
	bool create_files = false;
	unsigned long skip_count = 0, i;
	int dfd = -1;
	char *ptr;
	int arg;

	while ((arg = getopt_long(argc, argv, "c:dfhs:u:", long_opts, NULL)) != EOF) {
		switch (arg) {
			case 'c':
				ptr = optarg ? optarg : argv[optind];
				count_to_generate = strtol(ptr, NULL, 10);
				break;
			case 'd':
				create_dirs = true;
				break;
			case 'f':
				create_files = true;
				break;
			case 'u':
				ptr = optarg ? optarg : argv[optind];
				uuid = strdup(ptr);
				break;
			case 's':
				ptr = optarg ? optarg : argv[optind];
				skip_count = strtol(ptr, NULL, 10);
				break;
			case 'h': return usage(argv[0], EXIT_SUCCESS); break;
			default:
				return usage(argv[0], EXIT_FAILURE); break;
		}
	}

//	if (argc != 4) {
	if (argc != optind + 3)
		return usage(argv[0], EXIT_FAILURE);

	if (create_dirs || create_files)
		dfd = open("mnt", O_DIRECTORY|O_RDONLY);
	setlocale(LC_ALL, "en_US");

	name_len = strtol(argv[optind++], NULL, 10);
	min_hash = strtol(argv[optind++], NULL, 16);
	max_hash = strtol(argv[optind++], NULL, 16);

	if (uuid_parse(uuid, (unsigned char *)hash_seed)) {
		printf("error parsing uuid '%s': %m\n", uuid);
		return EXIT_FAILURE;
	}

	memset(filename_array, 0, sizeof(filename_array));
	for (count = 0 ; count < skip_count ; count++)
		incr_filename_array(name_len);
	for (i = 0 ; i < count_to_generate ; i++) {
		char *new_name = NULL;
		new_name = gen_new_name(name_len, min_hash, max_hash);

		if (new_name) {
			printf("%s\n", new_name);
			if (create_files) {
				int fd;

				if ((fd = openat(dfd, new_name, O_RDWR|O_CREAT, 0644)) < 0)
					printf("failed to create file: %m\n");
				if (fd >= 0)
					close(fd);
			}
			if (create_dirs) {
				if ((mkdirat(dfd, new_name, 0755)) < 0 && errno != EEXIST)
					printf("failed to create directory: %m\n");
			}
			free(new_name);
		}
	}

return 0;

	return EXIT_SUCCESS;
}
