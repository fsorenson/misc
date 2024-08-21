/*
	Frank Sorenson <sorenson@redhat.com>, 2024

	adapted from linux kernel code
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#define unlikely(x)	__builtin_expect((x),0)

#define CRC_LE_BITS 32

# define LE_TABLE_ROWS (CRC_LE_BITS/8)
# define LE_TABLE_SIZE 256

#define CRC32_POLY_LE 0xedb88320

static uint32_t crc32table_le[LE_TABLE_ROWS][256];
static void crc32init_le(void) {
	unsigned i, j;
	uint32_t crc = 1;

	crc32table_le[0][0] = 0;

	for (i = LE_TABLE_SIZE >> 1; i; i >>= 1) {
		crc = (crc >> 1) ^ ((crc & 1) ? CRC32_POLY_LE : 0);
		for (j = 0; j < LE_TABLE_SIZE; j += 2 * i)
			crc32table_le[0][i + j] = crc ^ crc32table_le[0][j];
	}
	for (i = 0; i < LE_TABLE_SIZE; i++) {
		crc = crc32table_le[0][i];
		for (j = 1; j < LE_TABLE_ROWS; j++) {
			crc = crc32table_le[0][crc & 0xff] ^ (crc >> 8);
			crc32table_le[j][i] = crc;
		}
	}
}

static inline uint32_t crc32_body(uint32_t crc, unsigned char const *buf, size_t len) {
#  define DO_CRC(x) crc = t0[(crc ^ (x)) & 255] ^ (crc >> 8)
#  define DO_CRC4 (t3[(q) & 255] ^ t2[(q >> 8) & 255] ^ \
		   t1[(q >> 16) & 255] ^ t0[(q >> 24) & 255])

	const uint32_t *b;
	size_t rem_len;
	size_t i;

	const uint32_t *t0 = crc32table_le[0], *t1 = crc32table_le[1],
		*t2 = crc32table_le[2], *t3 = crc32table_le[3];
	uint32_t q;

	/* Align it */
	if (unlikely((long)buf & 3 && len)) {
		do {
			DO_CRC(*buf++);
		} while ((--len) && ((long)buf)&3);
	}

	rem_len = len & 3;
	len = len >> 2;

	b = (const uint32_t *)buf;
	--b;
	for (i = 0; i < len; i++) {
		q = crc ^ *++b; /* use pre increment for speed */
		crc = DO_CRC4;
	}
	len = rem_len;
	/* And the last few bytes */
	if (len) {
		uint8_t *p = (uint8_t *)(b + 1) - 1;
		for (i = 0; i < len; i++)
			DO_CRC(*++p); /* use pre increment for speed */
	}
        return crc;
}
static inline uint32_t crc32_le(uint32_t crc, unsigned char const *p, int len) {
	crc = htole32(crc);
	crc = crc32_body(crc, p, len);
	crc = le32toh(crc);

	return crc;
}

#define NFS4_STATEID_OTHER_SIZE 12
static inline uint32_t nfs_stateid_hash(const unsigned char *sid_other) {
	return ~crc32_le(0xFFFFFFFF, &sid_other[0], NFS4_STATEID_OTHER_SIZE);
}

unsigned char hex_digit_val(unsigned char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 0xa;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 0xa;
	return 0;
}
char to_hex_digit(unsigned char c) {
	c = c & 0x0f;
	if (c < 0xa)
		return c + '0';
	if (c < 0x10)
		return c + 'a' - 0xa;
	return '0';
}

int main(int argc, char *argv[]) {
	crc32init_le();
	unsigned char hex_str[NFS4_STATEID_OTHER_SIZE + 1] = { 0 };
	char *p = &argv[1][0], new_str[NFS4_STATEID_OTHER_SIZE * 2 + 1] = { 0 };
	int len = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <hex_string>\n", argv[0]);
		return EXIT_FAILURE;
	}

	while (*p && len < NFS4_STATEID_OTHER_SIZE * 2 + 1) {
		if (isxdigit(*p)) {
			new_str[len++] = p[0];
		} else if (*p != ':') {
			fprintf(stderr, "invalid input ('%c' is not a hex digit)\n", p[0]);
			return EXIT_FAILURE;
		}
		p++;
	}
	if (len != NFS4_STATEID_OTHER_SIZE * 2) {
		fprintf(stderr, "invalid stateid length (%d); should be %d\n", len / 2, NFS4_STATEID_OTHER_SIZE);
		return EXIT_FAILURE;
	}
	p = new_str;
	len = 0;
	while (*p) {
		hex_str[len++] = (hex_digit_val(p[0]) << 4) | hex_digit_val(p[1]);
		p += 2;
	}

	printf("0x%08x\n", nfs_stateid_hash(hex_str));

	return EXIT_SUCCESS;
}
