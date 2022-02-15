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
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
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

static struct option long_options[] = {
	{ "threshold", required_argument, 0, 't' },
	{ NULL, 0, 0, 0 }
};


int main(int argc, char *argv[]) {
	unsigned char buf[BUF_SIZE], *p, *q;
	uint64_t read_offset = 0, null_byte_start_offset = 0;
	segment_type current_segment_type = in_data;
	int fd, opt, bytes_read, long_optind;
	int threshold = MIN_NULL_THRESH;
	char *filename = argv[1];

	while ((opt = getopt_long(argc, argv, "t:",
			long_options, &long_optind)) != -1) {
		switch (opt) {
			case 't':
				threshold = parse_size(optarg);
				break;
			default:
				output("error: unrecognized flag '%c'\n", opt);
				return EXIT_FAILURE;
				break;
		}
	}
	if (optind >= argc) {
		output("usage: %s [ -t <threshold> ] <filename>\n", argv[0]);
		return EXIT_FAILURE;
	}
	filename = argv[optind];

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

					if (null_byte_end_offset - null_byte_start_offset >= threshold)
						output("null bytes from offset %" PRIu64 " for length %" PRIu64 "\n",
							null_byte_start_offset, null_byte_end_offset - null_byte_start_offset);

					current_segment_type = in_data;
					null_byte_start_offset = 0;
				}
			}
		}
		read_offset += bytes_read;
	}
	if (bytes_read >= 0 && current_segment_type == in_nulls) { /* ended on nulls */
		if (read_offset - null_byte_start_offset >= threshold)
			output("null bytes from offset %" PRIu64 " for length %" PRIu64 "\n",
				null_byte_start_offset, read_offset - null_byte_start_offset);
	}
	if (bytes_read < 0)
		output("error reading: %m\n");
	return (bytes_read >= 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
