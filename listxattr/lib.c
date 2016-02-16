/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them as possible
*/

#include "lib.h"

int decode_flags(struct val_char_pair *flag_chars, ulong flags, char *buf) {
	uint64_t i = 0;
	char *bp = buf;

	while (flag_chars[i].c != '\0') {
		if (flags & flag_chars[i].val)
			*buf++ = flag_chars[i].c;
		i++;
	}
	*buf = '\0';
	return (buf - bp);
}

int decode_type(struct val_char_pair *types, ulong val, char *buf) {
	uint64_t i = 0;
	char *bp = buf;

	while (types[i].c != '\0') {
		if (val == types[i].val) {
			*buf++ = types[i].c;
			break;
		}
		i++;
	}
	*buf = '\0';
	return (buf - bp);
}

void hexprint(char *bytes, int len) {
	int i;
	int c;

	for (i = 0 ; i < len ; i ++) {
		c = bytes[i] & 0xFF;
		printf("'%c' %02x    ",
			isprint(c) ? c : '.',
			(unsigned int)c);
	}
	printf("\n");
}

