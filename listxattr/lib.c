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

void hexprint_pad(const char *pad, const unsigned char *buf, int len) {
	int line_len;
	int off = 0, i;

	while (off < len - 1) {
		printf("%s", pad);
		printf("%04x: ", off);
		line_len = min(16, len - off);

		for (i = 0 ; i < 16 ; i++) {
			if (i < line_len) {
				printf(" %02x", buf[off + i] & 0xff);
			} else
				printf("   ");

			if (i == 7)
				printf("  ");
		}
		printf(" | ");
		for (i = 0 ; i < 16 ; i++) {
			if (i < line_len)
				printf("%c", isprint(buf[off + i] & 0xff) ? buf[off + i] & 0xff : '.');
			else
				printf(" ");
		}
		printf("\n");
		off += line_len;
	}
}

void hexprint(const unsigned char *buf, int len) {
	hexprint_pad("", buf, len);
}

bool printable(const unsigned char *buf, int len) {
	int i = len - 1;

	if (i < 0)
		return false;

	while (i >= 0) {
		if (! isprint(buf[i--]))
			return false;
	}
	return true;
}

int hexchr2bin(const char hex, char *out) {
	if (out == NULL)
		return 0;
	if (hex >= '0' && hex <= '9')
		*out = hex - '0';
	else if (hex >= 'a' && hex <= 'f')
		*out = hex - 'a' + 10;
	else if (hex >= 'A' && hex <= 'F')
		*out = hex - 'A' + 10;
	else
		return 0;
	return 1;
}

unsigned char *dehexlify_string1(char *string) {
	unsigned char *new_buf = NULL;
	int len = strlen(string), i;

	if (len % 1) {
		printf("error: invalid hex string to decode (odd number of hex digits: %d)\n\t%s\n",
			len, string);
		goto out;
	}
	new_buf = malloc(len / 2);

	for (i = 0 ; i < len ; i += 2) {
		char out[2] = { '\0', '\0' };
		hexchr2bin(string[i], &out[0]);
		hexchr2bin(string[i + 1], &out[1]);
//		new_buf[i/2] = hexchr2bin(string[i]) << 4 | hexchr2bin(string[i + 1]);
		new_buf[i/2] = out[0] << 4 | out[1];
	}

	printf("hex string is %d long, attr is %d long\n", len, len/2);
	hexprint(new_buf, len/2);

out:
	return new_buf;
}
unsigned char *dehexlify_string2(char *string) {
	unsigned char *buf = NULL;
	int len = strlen(string), i;

	if (len % 1) {
		printf("error: invalid hex string to decode (odd number of hex digits: %d)\n\t%s\n",
			len, string);
		goto out;
	}
	len /= 2;
	buf = malloc(len);
//	memset(buf, 0, len);
	memset(buf, 'A', len); // why 'A' ?

	for (i = 0 ; i < len ; i++) {
		char b1, b2;
		hexchr2bin(string[i*2], &b1);
		hexchr2bin(string[i*2 + 1], &b2);
		buf[i] = (b1 << 4) | b2;
	}
out:
	return buf;
}

unsigned char *dehexlify_string(char *string) {
	return dehexlify_string2(string);
}




size_t b64_encoded_size(size_t inlen) {
	size_t ret;

	ret = inlen;
	if (inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;

	return ret;
}
const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char *base64ify(const unsigned char *in, size_t len) {
	char *out;
	size_t elen, i, j, v;

	if (!in || len == 0)
		return NULL;

	elen = b64_encoded_size(len);
	out = malloc(elen+1);
	out[elen] = '\0';

	for (i = 0 , j = 0 ; i < len ; i+=3 , j+=4) {
		v = in[i];
		v = (i+1 < len) ? v << 8 | in[i+1] : v << 8;
		v = (i+2 < len) ? v << 8 | in[i+2] : v << 8;

		out[j]   = b64chars[(v >> 18) & 0x3F];
		out[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len)
			out[j+2] = b64chars[(v >> 6) & 0x3F];
		else
			out[j+2] = '=';
		if (i+2 < len)
			out[j+3] = b64chars[v & 0x3F];
		else
			out[j+3] = '=';
	}
	return out;
}

int debase64_len(const char *str) {
	size_t len, ret, i;

	if (!str)
		return 0;
	len = strlen(str);
	ret = len / 4 * 3;

	for (i = len ; i-- > 0 ; ) {
		if (str[i] == '=')
			ret--;
		else
			break;
	}
	return ret;
}
int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
	59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51 };
bool b64_isvalidchar_old(char c) {
	if (c >= '0' && c <= '9')
		return true;
	if (c >= 'A' && c <= 'Z')
		return true;
	if (c >= 'a' && c <= 'z')
		return true;
	if (c == '+' || c == '/' || c == '=')
		return true;
	return false;
}
bool b64_isvalidchar(unsigned char c) {
	switch (c) {
		case '0'...'9':
		case 'A' ... 'Z':
		case 'a' ... 'z':
		case '+':
		case '/':
		case '=':
//			printf("valid character: '%c'\n", c);
			return true;
			break;
		default:
//			printf("invalid character: %d\n", c);
			return false;
			break;
	};
//	printf("got no match?\n");
}
unsigned char *debase64ify(char *str) {
	unsigned char *out = NULL;

	size_t len, i, j;
	int v;

//	printf("about to decode %s\n", str);

	if (!str)
		return 0;

	len = strlen(str);
//	printf("len: %lu\n", len);
	if (len % 4)
		return 0;

//	printf("here\n");
	for (i = 0 ; i < len ; i++) {
//		printf("checking '%c'\n", str[i]);
		if (!b64_isvalidchar(str[i]))
			return 0;
	}
//	printf("here2\n");

	out = malloc(debase64_len(str));
//	printf("allocated decode buffer at %p\n", out);
	for (i = 0 ,  j = 0 ; i < len ; i+=4 , j+=3) {
		v = b64invs[str[i]-43];
		v = (v << 6) | b64invs[str[i+1]-43];
		v = str[i+2]=='=' ? (v << 6) : (v << 6) | b64invs[str[i+2]-43];
		v = str[i+3]=='=' ? (v << 6) : (v << 6) | b64invs[str[i+3]-43];

		out[j] = (v >> 16) & 0xff;
		if (str[i+2] != '=')
			out[j+1] = (v >> 8) & 0xff;
		if (str[i+3] != '=')
			out[j+2] = v & 0xff;
	}
	return out;
}
