/*
	Frank Sorenson <sorenson@redhat.com>, 2022

	find_zeros.c - search a file for sequences of bytes containing NULL

	$ gcc find_zeros.c -o find_zeros
	$ ./find_zeros [ -t <threshold> ] /path/to/file

	where threshold is the number of sequential zeros before reporting - defaults to 100

	for example:

		$ perl -e 'printf "%s%s%s%s%s%s%s", "X"x32768, "\0"x4096, "X"x10480, "\0"x50, "X"x8000, "\0"x5000, "X"x32768' >testfile

		$ ./find_zeros testfile
		null bytes from offset 32768 for length 4096
		null bytes from offset 55394 for length 5000

		$ find_zeros -t 50 testfile
		null bytes from offset 32768 for length 4096
		null bytes from offset 47344 for length 50
		null bytes from offset 55394 for length 5000
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>

#define KiB	(1024ULL)
#define MiB	(KiB * KiB)

#define DEBUG 0

#define BUF_SIZE MiB

/* a file could legit have a sequence of NULL bytes -- don't care unless we have this many in a row */
#define MIN_NULL_THRESH	100

typedef enum { in_data, in_nulls } segment_type;
typedef enum { fmt_hex, fmt_decimal } offset_fmt;

struct config {
	uint64_t threshold;
	offset_fmt fmt;
	bool quiet;
	bool show_filename;
	bool recurse;
	bool human;		/* show sizes in human-readable form */
	uint64_t agsize;	/* AG size in fs blocks; 0 = no XFS annotation */
	uint64_t blocksize;	/* fs block size in bytes */
};

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

/* returns a size in bytes */
uint64_t parse_size(const char *size_str) {
	uint64_t size = 0;
	int shift = 0;
	char *p;

	size = strtoull(size_str, &p, 10);

	while (*p != '\0' && (*p == '.' || *p == ' '))
		p++;
	if (*p != '\0') {
		if (strlen(p) <= 3) {
			if (strlen(p) == 2 && tolower(*(p+1)) != 'b')
				goto out_badsize;
			else if (strlen(p) == 3 &&
				(tolower(*(p+1)) != 'i' || tolower(*(p+2)) != 'b'))
				goto out_badsize;

			switch (tolower(*p)) {
				/* can't actually represent these */
				case 'y':
				case 'z':
					output("size too large: %s\n", p);
					return 0;
					break;;
				case 'e': shift++;
				case 'p': shift++;
				case 't': shift++;
				case 'g': shift++;
				case 'm': shift++;
				case 'k':
					shift++;
					break;;
				default:
					goto out;
					break;;
			}
		} else
			goto out_badsize;
	}
	if (shift)
		size = size * (1ULL << (shift * 10));
out:
	return size;

out_badsize:
	output("unrecognized size: '%s'\n", p);
	return 0;
}

static const char *format_size(uint64_t size) {
	static char buf[32];
	static const char * const units[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" };
	int u = 0;
	double s = size;

	while (s >= 1024.0 && u < 6) {
		s /= 1024.0;
		u++;
	}
	if (u == 0)
		snprintf(buf, sizeof(buf), "%" PRIu64 " B", size);
	else
		snprintf(buf, sizeof(buf), "%.2f %s", s, units[u]);
	return buf;
}

static const char *xfs_ag_block_name(uint64_t block) {
	switch (block) {
		case 0: return "SB";
		case 1: return "AGF";
		case 2: return "AGI";
		case 3: return "AGFL";
		default: return NULL;
	}
}

static void report_xfs_annotation(uint64_t offset, uint64_t len, const struct config *cfg) {
	uint64_t ag_size_bytes = cfg->agsize * cfg->blocksize;
	uint64_t end = offset + len;
	uint64_t ag_num = offset / ag_size_bytes;
	uint64_t ag_offset_bytes = offset % ag_size_bytes;
	uint64_t ag_block = ag_offset_bytes / cfg->blocksize;
	uint64_t ag_block_offset = ag_offset_bytes % cfg->blocksize;
	const char *name = ag_block_offset == 0 ? xfs_ag_block_name(ag_block) : NULL;

	if (name)
		output("  [AG %" PRIu64 ", block %" PRIu64 ": %s]", ag_num, ag_block, name);
	else if (ag_block_offset == 0)
		output("  [AG %" PRIu64 ", block %" PRIu64 "]", ag_num, ag_block);
	else
		output("  [AG %" PRIu64 ", offset 0x%" PRIx64 "]", ag_num, ag_offset_bytes);

	/* report any AG starts whose block 0 falls within this zero region */
	for (uint64_t n = ag_num + 1; n * ag_size_bytes < end; n++) {
		uint64_t ag_start = n * ag_size_bytes;
		const char *sep = "";
		output("\n  includes AG %" PRIu64 ":", n);
		for (int b = 0; b <= 3 && ag_start + (uint64_t)b * cfg->blocksize < end; b++) {
			output("%s %s", sep, xfs_ag_block_name(b));
			sep = ",";
		}
	}
}

/* returns true if the caller should stop scanning */
static bool report_region(const char *filename, uint64_t start, uint64_t len,
		const struct config *cfg) {
	if (cfg->quiet) {
		output("%s\n", filename);
		return true;
	}
	if (cfg->show_filename)
		output("%s: ", filename);
	if (cfg->fmt == fmt_hex)
		output("null bytes from offset 0x%" PRIx64, start);
	else
		output("null bytes from offset %" PRIu64, start);
	if (cfg->human)
		output(" for length %s", format_size(len));
	else if (cfg->fmt == fmt_hex)
		output(" for length 0x%" PRIx64, len);
	else
		output(" for length %" PRIu64, len);
	if (cfg->agsize)
		report_xfs_annotation(start, len, cfg);
	output("\n");
	return false;
}

static struct option long_options[] = {
	{ "threshold",      required_argument, 0, 't' },
	{ "decimal",        no_argument,       0, 'd' },
	{ "hex",            no_argument,       0, 'x' },
	{ "quiet",          no_argument,       0, 'q' },
	{ "recurse",        no_argument,       0, 'r' },
	{ "human-readable", no_argument,       0, 'h' },
	{ "agsize",         required_argument, 0, 'a' },
	{ "blocksize",      required_argument, 0, 'B' },
	{ NULL, 0, 0, 0 }
};

int find_zeros_in_file(const char *filename, const struct config *cfg) {
	unsigned char buf[BUF_SIZE], *p, *q;
	uint64_t read_offset = 0, null_byte_start_offset = 0;
	segment_type current_segment_type = in_data;
	int fd, bytes_read;

	if ((fd = open(filename, O_RDONLY)) < 0) {
		output("error opening '%s': %m\n", filename);
		return EXIT_FAILURE;
	}
	while ((bytes_read = read(fd, buf, BUF_SIZE)) > 0) {

		p = buf;
		while (p < buf + BUF_SIZE) {
			if (current_segment_type == in_data) {
				if ((q = memchr(p, '\0', bytes_read - (p - buf))) != NULL) { /* found null byte */
					null_byte_start_offset = read_offset + q - buf;
					current_segment_type = in_nulls;

					if (DEBUG)
						output("null bytes starting at offset %" PRIu64 "\n", null_byte_start_offset);
					p = q;
				} else
					break;
			} else {
				while (p < buf + BUF_SIZE && *p == '\0')
					p++;
				if (p < buf + BUF_SIZE && *p != '\0') { /* found a non-null */
					uint64_t null_byte_end_offset = read_offset + p - buf;

					if (DEBUG)
						output("non-null bytes starting at offset %" PRIu64 "\n", null_byte_end_offset);

					if (null_byte_end_offset - null_byte_start_offset >= cfg->threshold) {
						if (report_region(filename, null_byte_start_offset,
								null_byte_end_offset - null_byte_start_offset, cfg)) {
							close(fd);
							return EXIT_SUCCESS;
						}
					}

					current_segment_type = in_data;
					null_byte_start_offset = 0;
				}
			}
		}
		read_offset += bytes_read;
	}
	if (bytes_read >= 0 && current_segment_type == in_nulls) { /* ended on nulls */
		if (read_offset - null_byte_start_offset >= cfg->threshold)
			report_region(filename, null_byte_start_offset,
				read_offset - null_byte_start_offset, cfg);
	}
	if (bytes_read < 0)
		output("error reading: %m\n");
	close(fd);
	return (bytes_read >= 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int process_path(const char *path, const struct config *cfg, dev_t xdev);

static int process_directory(const char *path, const struct config *cfg, dev_t xdev) {
	DIR *dir = opendir(path);
	if (!dir) {
		output("error opening directory '%s': %m\n", path);
		return EXIT_FAILURE;
	}

	int ret = EXIT_SUCCESS;
	struct dirent *ent;
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;

		char child_path[PATH_MAX];
		snprintf(child_path, sizeof(child_path), "%s/%s", path, ent->d_name);

		if (process_path(child_path, cfg, xdev) != EXIT_SUCCESS)
			ret = EXIT_FAILURE;
	}
	closedir(dir);
	return ret;
}

static int process_path(const char *path, const struct config *cfg, dev_t xdev) {
	struct stat st;
	if (lstat(path, &st) < 0) {
		output("error stating '%s': %m\n", path);
		return EXIT_FAILURE;
	}

	if (xdev && st.st_dev != xdev)
		return EXIT_SUCCESS;

	if (S_ISREG(st.st_mode) || S_ISBLK(st.st_mode))
		return find_zeros_in_file(path, cfg);
	else if (S_ISDIR(st.st_mode)) {
		if (cfg->recurse)
			return process_directory(path, cfg, st.st_dev);
		output("'%s': skipping directory\n", path);
	} else if (S_ISLNK(st.st_mode))
		output("'%s': skipping symlink\n", path);
	else if (S_ISCHR(st.st_mode))
		output("'%s': skipping character device\n", path);
	else if (S_ISSOCK(st.st_mode))
		output("'%s': skipping socket\n", path);
	else if (S_ISFIFO(st.st_mode))
		output("'%s': skipping FIFO\n", path);
	else
		output("'%s': skipping unknown file type\n", path);
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
	struct config cfg = {
		.threshold = MIN_NULL_THRESH,
		.fmt       = fmt_hex,
		.quiet     = false,
		.recurse   = false,
		.human     = false,
		.agsize    = 0,
		.blocksize = 4096,
	};
	int opt, long_optind;

	while ((opt = getopt_long(argc, argv, "t:dxqrha:B:",
			long_options, &long_optind)) != -1) {
		switch (opt) {
			case 't':
				cfg.threshold = parse_size(optarg);
				break;
			case 'd':
				cfg.fmt = fmt_decimal;
				break;
			case 'x':
				cfg.fmt = fmt_hex;
				break;
			case 'q':
				cfg.quiet = true;
				break;
			case 'r':
				cfg.recurse = true;
				break;
			case 'h':
				cfg.human = true;
				break;
			case 'a':
				cfg.agsize = strtoull(optarg, NULL, 0);
				break;
			case 'B':
				cfg.blocksize = parse_size(optarg);
				break;
			default:
				output("error: unrecognized flag '%c'\n", opt);
				return EXIT_FAILURE;
				break;
		}
	}
	if (optind >= argc) {
		output("usage: %s [ -t <threshold> ] [ -d | -x ] [ -h ] [ -q ] [ -r ] [ -a <agsize_blocks> [ -B <blocksize> ] ] <file> [<file> ...]\n", argv[0]);
		return EXIT_FAILURE;
	}

	cfg.show_filename = cfg.recurse || (argc - optind > 1);

	int ret = EXIT_SUCCESS;
	for (int i = optind; i < argc; i++) {
		if (process_path(argv[i], &cfg, 0) != EXIT_SUCCESS)
			ret = EXIT_FAILURE;
	}
	return ret;
}
