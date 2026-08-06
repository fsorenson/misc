/*
	Frank Sorenson <sorenson@redhat.com>, 2026

	dump_core.c - allocate the specified amount of memory, then dump core
*/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

/* parse_size copied from test_disk_writes.c */
static uint64_t parse_size(const char *size_str) {
	uint64_t uint_size = 0, ret;
	long double size;
	int shift = 0, have_uint = 0;
	char *p;

	uint_size = strtoull(size_str, NULL, 10);
	size = strtold(size_str, &p);

	if (fabsl((long double)uint_size - size) < 1e-9)
		have_uint = 1; /* integer, or close enough */

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
				case 'y':
				case 'z':
					printf("size too large: %s\n", p);
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
	if (have_uint && shift)
		ret = uint_size * (1ULL << (shift * 10));
	else if (have_uint)
		ret = uint_size;
	else if (shift)
		ret = (uint64_t)(size * (long double)(1ULL << (shift * 10)));
	else
		ret = uint_size;
out:
	return ret;

out_badsize:
	printf("unrecognized size: '%s'\n", p);
	return 0;
}

int main(int argc, char *argv[]) {
	uint64_t size;
	void *mem;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <size>\n", argv[0]);
		fprintf(stderr, "  size: bytes, with optional suffix (K, M, G, T, ...)\n");
		fprintf(stderr, "  examples: 512M, 2G, 1.5G, 4096\n");
		return EXIT_FAILURE;
	}

	size = parse_size(argv[1]);
	if (!size) {
		fprintf(stderr, "%s: invalid size '%s'\n", argv[0], argv[1]);
		return EXIT_FAILURE;
	}

	printf("allocating %" PRIu64 " bytes (%.2f MiB)...\n",
		size, (double)size / (1024.0 * 1024.0));

	mem = malloc(size);
	if (!mem) {
		fprintf(stderr, "%s: malloc(%" PRIu64 ") failed\n", argv[0], size);
		return EXIT_FAILURE;
	}

	/* touch every page so the allocation is present in the core dump */
	memset(mem, 0xab, size);

	printf("dumping core\n");
	fflush(stdout);
	abort();

	return EXIT_SUCCESS; /* not reached */
}
