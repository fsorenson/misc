/*
	Frank Sorenson <sorenson@redhat.com>, 2020

	make_sparse - program to un-sparse a file in-place

	Finds the 'holes' in a sparse file, and write zeros to the
	file in their place

	essentially the exact opposite of what fallocate does with:
	$ fallocate --dig-holes --keep-size <filename>

	$ gcc make_unsparse.c -o make_unsparse
	$ ./make_unsparse <file_to_make_unsparse>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)
#define TiB (KiB * KiB * KiB * KiB)

#define BUF_SIZE (1 * MiB)

int usage(int argc, char *argv[], int ret) {
	printf("usage: %s [-v | --verbose ] [ -q | --quiet ] [ -n | --dry-run ] [ -d | --check-space ] [ <file_to_make_unsparse>\n", argv[0]);
	printf("\t-h | --help - show this help message\n");
	printf("\t-v | --verbose - increase verbosity (may be specified more than once)\n");
	printf("\t-q | --quiet - decrease verbosity\n");
	printf("\t-n | --dry-run - go through the motions, but do not actually make changes\n");
	printf("\t\t(useful for testing whether holes exist,\n");
	printf("\t\t and/or whether there is enough disk space)\n");

	printf("\t-d | --check-space - test whether disk space is available\n");
	printf("\t\tto contain the newly-occupied holes\n");
	printf("\t-f | --force - force execution, even if disk space is not available\n");
	printf("\t\t(note: a disk write will most likely fail)\n");
	return ret;
}

struct config_struct {
	int verbosity;
	bool check_space;
	bool dry_run;
	bool help_only;
	bool force;
	char *file_path;
} config = {
	.verbosity = 0,
	.help_only = false,
	.check_space = false,
	.dry_run = false,
	.force = false,
	.file_path = NULL
};

int parse_args(int argc, char *argv[]) {
	static struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "quiet", no_argument, NULL, 'q' },
		{ "dry-run", no_argument, NULL, 'n'},
		{ "check-space", no_argument, NULL, 'c' },
		{ "force", no_argument, NULL, 'f' },
		{ NULL, 0, NULL, 0}
	};
	int opt;

	while (42) {
		opt = getopt_long(argc, argv, "hvqncf", long_options, &optind);
		if (opt == -1)
			break;
		switch (opt) {
			case 'h':
				config.help_only = true;
				return EXIT_SUCCESS;
			case 'v':
				config.verbosity++;
				break;
			case 'q':
				if (config.verbosity > 0)
					config.verbosity--;
				break;
			case 'n':
				config.dry_run = true;
				break;
			case 'c':
				config.check_space = true;
				break;
			case 'f':
				config.force = true;
				break;
			default:
				printf("unknown argument: %c\n", opt);
				break;
		}
	}
	return EXIT_SUCCESS;
}

uint64_t l1024(uint64_t x) {
        uint64_t r = __builtin_clzll(x);
	if (x < 1024)
		return 0;
        if (r == (sizeof(x)*8ul))
                return 0;
        return ((sizeof(x)*8ul) - 1 - r) / 10;
}
#define units_base 1024
static char *unit_strings[] = { " bytes", "KiB", "MiB", "GiB", "GiB", "GiB", "EiB", "ZiB", "YiB" };
char *byte_units(uint64_t size) {
	char *ret;
	uint64_t divider;
	uint64_t d, rem;

	if (size < units_base) {
		asprintf(&ret, "%" PRIu64 " bytes", size);
	} else {
		int i = l1024(size);
		if (i > (sizeof(unit_strings)/sizeof(unit_strings[0])))
			i = sizeof(unit_strings)/sizeof(unit_strings[0]);

		divider = 1ul << (i * 10ul);

		d = size / divider;
		rem = size - (d * divider);
		rem = (rem * 100) / divider;

		asprintf(&ret, "%" PRIu64 ".%02" PRIu64 " %s",
			d, rem, unit_strings[i]);
	}
	return ret;
}
uint64_t get_disk_free(const char *path, uint64_t *fs_free) {
	struct statvfs st_vfs;

	if ((statvfs(path, &st_vfs)) < 0) {
		printf("unable to stat the filesystem for '%s': %m\n", path);
		return EXIT_FAILURE;
	}
	*fs_free = st_vfs.f_bsize * st_vfs.f_bfree;
	return EXIT_SUCCESS;
}

int execute(uint64_t *new_disk_required) {
	uint64_t holes_chewed = 0;
	uint64_t current_pos = 0;
	int open_opts = O_RDWR;
	int ret = EXIT_SUCCESS;
	uint64_t file_size;
	uint64_t new_pos;
	char *buf = NULL;
	size_t len;
	int fd;

	if (new_disk_required)
		open_opts = O_RDONLY;
	else {
		if (! (buf = malloc(BUF_SIZE))) {
			printf("failed to allocate %llu bytes for buffer\n", BUF_SIZE);
			ret = EXIT_FAILURE;
			goto out;
		}
		memset(buf, 0, BUF_SIZE);
	}

	if ((fd = open(config.file_path, open_opts)) < 0) {
		printf("error opening file: %m\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	file_size = lseek(fd, 0, SEEK_END);
	current_pos = lseek(fd, 0, SEEK_SET);
	while (42) {
		if (current_pos == file_size)
			break;
		if ((new_pos = lseek(fd, current_pos, SEEK_HOLE)) == (off_t)(-1)) {
			if (errno != ENXIO) {
				printf("lseek(%d, %lu, SEEK_HOLE) failed with %m\n",
					fd, current_pos);
				ret = EXIT_FAILURE;
				goto out;
			}
			break;
		}
		len = new_pos - current_pos;
		if (config.verbosity > 1)
			printf("data from %lu to %lu (%lu bytes)\n", current_pos, new_pos, len);

		current_pos = new_pos;

		if ((new_pos = lseek(fd, current_pos, SEEK_DATA)) == (off_t)(-1)) {
			if (errno == ENXIO && current_pos < file_size) { /* file ends with a hole */
				new_pos = file_size;
			} else {
				if (errno != ENXIO) {
					printf("lseek(%d, %lu, SEEK_DATA) failed with %m\n",
						fd, current_pos);
					ret = EXIT_FAILURE;
					goto out;
				}
				break;
			}
		}

		len = new_pos - current_pos;
		if (config.verbosity > 1)
			printf("hole from %lu to %lu (%lu bytes)\n", current_pos, new_pos, len);

		if (new_disk_required)
			*new_disk_required += len;
		else while (current_pos < new_pos) {
			uint64_t this_write_len = new_pos - current_pos;

			if (this_write_len > BUF_SIZE)
				this_write_len = BUF_SIZE;
			if ((pwrite(fd, buf, this_write_len, current_pos)) < 0) {
				if (errno == ENOSPC || errno == EDQUOT || errno == EIO) {
					printf("write failed due to %s\n",
						errno == ENOSPC ? "full disk" :
						errno == EDQUOT ? "disk quota" :
						errno == EIO ? "IO error" :
						"aliens, probably");
					ret = EXIT_FAILURE;
					goto out;
				} else { /* maybe just wrap this in the previous print statement? */
					printf("write failed: %m\n");
				}
			}
			current_pos += this_write_len;
		}

/*
		if ((fallocate(fd, FALLOC_FL_KEEP_SIZE|FALLOC_FL_ZERO_RANGE, current_pos, len)) < 0) {
			printf("fallocate returned an error: %m\n");
		}
*/
		holes_chewed++;
		current_pos = new_pos;
	}
out:
	if (fd >= 0)
		close(fd);

	if (ret == EXIT_SUCCESS) {
		if (config.verbosity > 1 && errno == ENXIO)
			printf("looks like we're complete\n");

		if (config.verbosity > 0 && ! holes_chewed)
			printf("no holes found\n");
		else if (config.verbosity > 0 && ! config.dry_run)
			printf("chewed %lu hole%s\n", holes_chewed, holes_chewed == 1 ? "" : "s");
	}

	if (! new_disk_required)
		free(buf);

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {

	if (parse_args(argc, argv) != EXIT_SUCCESS)
		return usage(argc, argv, EXIT_FAILURE);
	else if (config.help_only)
		return usage(argc, argv, EXIT_SUCCESS);

	if (optind >= argc) {
		printf("no file specified\n");
		return usage(argc, argv, EXIT_FAILURE);
	}
	config.file_path = canonicalize_file_name(argv[optind]);
	if (! config.file_path) {
		printf("unable to find file '%s': %m\n", argv[optind]);
		return EXIT_FAILURE;
	}
	if (config.check_space) {
		uint64_t new_disk_required = 0;
		uint64_t fs_free;

		if ((get_disk_free(config.file_path, &fs_free)) == EXIT_FAILURE)
			return EXIT_FAILURE;

		if ((execute(&new_disk_required)) == EXIT_FAILURE)
			return EXIT_FAILURE;

		if (fs_free < new_disk_required) {
			char *size_str = byte_units(new_disk_required - fs_free);


			printf("Insufficient disk space to unsparse '%s'; need %s more\n",
				config.file_path, size_str);
			free(size_str);
			if (! config.force)
				return EXIT_FAILURE;
			printf("attempt to unsparse forced; this may fail due to insufficient disk space remaining\n");
		}
	}

	if (! config.dry_run)
		return execute(NULL);

	return EXIT_SUCCESS;
}
