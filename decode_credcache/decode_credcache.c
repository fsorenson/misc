#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <endian.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

#define min(a,b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a < _b ? _a : _b; \
})

struct buf_config {
	uint8_t *buf;
	uint32_t size;
};

struct hdr4_field {
	uint16_t tag;
	uint16_t len;
	char data[0];
};
struct hdr4_field_tag1 {
	uint16_t tag;
	uint16_t len;
	uint32_t sec;
	uint32_t msec;
};

struct v4_hdr {
	uint16_t len;
	struct hdr4_field fields[0];
};

struct data {
	uint32_t len;
	uint8_t *value;
};

struct principal {
	uint32_t type;
	uint32_t count;
	struct data realm;
	struct data *components;
};
struct keyblock {
	uint16_t enctype;
	struct data data;
};
struct address {
	uint16_t addrtype;
	struct data data;
};
struct addresses {
	uint32_t count;
	struct address address[0];
};

struct authdata {
	uint16_t ad_type;
	struct data data;
};
struct authdatas {
	uint32_t count;
	struct authdata authdata[0];
};

struct credential {
	struct principal *client;
	struct principal *server;
	struct keyblock keyblock;
	uint32_t authtime;
	uint32_t starttime;
	uint32_t endtime;
	uint32_t renew_till;
	uint8_t is_skey;
	uint32_t ticket_flags;
	struct addresses *addresses;
	struct authdatas *authdata;
	struct data ticket;
	struct data second_ticket;
};

struct ticket_flags_types {
	uint32_t flag;
	char ch;
	char *str;
};
static struct ticket_flags_types[] = {
	{ TKT_FLG_FORWARDABLE, 'F', "Forwardable" },
	{ TKT_FLG_FORWARDED, 'f', "Forwarded" },
	{ TKT_FLG_PROXIABLE, 'P', "Proxiable" },
	{ TKT_FLG_PROXY, 'p', "Proxy" },
	{ TKT_FLG_MAY_POSTDATE, 'D', "May Postdate" },
	{ TKT_FLG_POSTDATED, 'd', "Postdated" },
	{ TKT_FLG_INVALID, 'i', "Invalid" },
	{ TKT_FLG_RENEWABLE, 'R', "Renewable" },
	{ TKT_FLG_INITIAL, 'I', "Initial" },
	{ TKT_FLG_HW_AUTH, 'H', "HW Auth" },
	{ TKT_FLG_PRE_AUTH, 'A', "PreAuth" },
	{ TKT_FLG_TRANSIT_POLICY_CHECKED, 'T', "Transit Policy Checked" },
	{ TKT_FLG_OK_AS_DELEGATE, 'O', "Okay as Delegate" },
	{ TKT_FLG_ANONYMOUS, 'a', "Anonymous" },
};
static char *flags_string(uint32_t flags) {
	static char buf[32], *p = buf;
	int i = 0;

	for (i = 0 ; i < sizeof(ticket_flag_types)/sizeof(ticket_flag_types[0]) ; i++) {
		if (flags & ticket_flags_types[i].flag)
			*p++ = ticket_flags_types[i].ch;
	}
	*p = '\0';
}

const char *krb5_princ_type_str(int type) {
	static char unk_str[16];
	switch (type) {
		case 1: return "PRINCIPAL"; break;
		case 2: return "SRV_INST"; break;
		case 3: return "SRV_HST"; break;
		case 4: return "SRV_XHST"; break;
		case 5: return "UID"; break;
		case 6: return "X500_PRINCIPAL"; break;
		case 7: return "SMTP_NAME"; break;
		case 10: return "ENTERPRISE_PRINCIPAL"; break;
		case 11: return "WELLKNOWN"; break;
		case 0: return "UNKNOWN"; break;
		default:
	}
	snprintf(unk_str, sizeof(unk_str) - 1, "UNKNOWN type %d", type);
	return unk_str;
}
const char *enctype_str(int type) {
	static char unk_str[8];
	switch (type) {
		case 17: return "aes128-cts-hmac-sha1-96"; break;
		case 18: return "aes256-cts-hmac-sha1-96"; break;
		case 19: return "aes128-cts-hmac-sha256-128"; break;
		case 20: return "aes256-cts-hmac-sha384-192"; break;
		default:
	}
	snprintf(unk_str, sizeof(unk_str) - 1, "type %d", type);
	return unk_str;
}

			#define KRB5_NT_UNKNOWN        0 /**<  Name type not known */
#define KRB5_NT_PRINCIPAL      1 /**< Just the name of the principal
                                      as in DCE, or for users */
#define KRB5_NT_SRV_INST       2 /**< Service and other unique instance (krbtgt) */
#define KRB5_NT_SRV_HST        3 /**< Service with host name as instance
                                      (telnet, rcommands) */
#define KRB5_NT_SRV_XHST       4 /**< Service with host as remaining components */
#define KRB5_NT_UID            5 /**< Unique ID */
#define KRB5_NT_X500_PRINCIPAL 6 /**< PKINIT */
#define KRB5_NT_SMTP_NAME      7 /**< Name in form of SMTP email name */
#define KRB5_NT_ENTERPRISE_PRINCIPAL  10        /**< Windows 2000 UPN */
#define KRB5_NT_WELLKNOWN      11 /**< Well-known (special) principal */
#define KRB5_WELLKNOWN_NAMESTR "WELLKNOWN" /**< First component of */



int read_buf2(int fd, struct buf_config *buf, int read_size) {
	int ret;

	if (read_size > buf->size) {
		uint8_t *new_buf = realloc(buf->buf, read_size);
		if (read_size > 0 && new_buf == NULL) {
			printf("error expanding memory from %u to %u bytes: %m\n",
				buf->size, read_size);
			exit(-1);
		}
		buf->buf = new_buf;
		buf->size = read_size;
	}
	ret = read(fd, buf->buf, read_size);
	if (ret != read_size) {
		printf("read %d bytes, but expected %d: %m\n", ret, read_size);
	}
	return ret;
}


#define read_buf(_fd, _buf, _read_size, _buf_size) ({ \
	int _read; \
	if (_read_size > _buf_size) { \
		uint8_t *new_array = realloc(_buf, _read_size); \
		if (_read_size > 0 && new_array == NULL) { \
			printf("error expanding memory from %u to %u bytes: %m\n", (uint32_t)_buf_size, (uint32_t)_read_size); \
			exit (-1); \
		} \
		_buf = new_array; \
		_buf_size = _read_size; \
	} \
	_read = read(_fd, _buf, _read_size); \
	if (_read != _read_size) { \
		printf("read %d bytes, but expected %d\n", _read, (int)_read_size); \
	} \
	_read; \
})
#define print_str(_buf, _len) do { \
	int i; \
	for (i = 0 ; i < _len ; i++) \
		printf("%c", _buf[i]); \
} while (0)
void print_hexdump(const char *pre, const uint8_t *addr, size_t len) {
	size_t offset = 0;
	char buf[17];
	int i;

	while (offset < len) {
		int this_count = min(len - offset, 16);

		memcpy(buf, addr + offset, this_count);
		printf("%s0x%08lx: ", pre, offset);
		for (i = 0 ; i < 16 ; i++) {
			if (i < this_count)
				printf("%02x ", buf[i] & 0xff);
			else
				printf("   ");
			if (i == 7)
				printf("| ");
			if (i >= this_count)
				buf[i] = '\0';
			else if (! isprint(buf[i]))
				buf[i] = '.';
		}
		buf[i] = '\0';
		printf(" |%s|\n", buf);
		offset += this_count;
        }
}
off_t file_pos(int fd) {
	return lseek(fd, 0, SEEK_CUR);
}
bool is_eof(int fd) {
	struct stat st;

	fstat(fd, &st);
	if (file_pos(fd) >= st.st_size)
		return true;
	return false;
}


uint8_t read_uint8(int fd, struct buf_config *buf) {
	read_buf2(fd, buf, sizeof(uint8_t));
	return buf->buf[0];
}
uint16_t read_uint16(int fd, struct buf_config *buf) {
	read_buf2(fd, buf, sizeof(uint16_t));
	return be16toh(*(uint16_t *)buf->buf);
}
uint32_t read_uint32(int fd, struct buf_config *buf) {
	read_buf2(fd, buf, sizeof(uint32_t));
	return be32toh(*(uint32_t *)buf->buf);
}
void *memdup(uint8_t *src, int len, bool null_terminate) {
	uint8_t *dst = malloc(len + (null_terminate ? 1 : 0));
	memset(dst, 0, len + (null_terminate ? 1 : 0));
	memcpy(dst, src, len);
	return dst;
}
void *read_data(int fd, struct buf_config *buf, int len) {
	read_buf2(fd, buf, len);
	return memdup(buf->buf, len, false);
}

int read_show_header(int fd, struct buf_config *buf) {
	// header for format version 4
	uint16_t len = read_uint16(fd, buf);

	int remaining_len = len - sizeof(uint16_t);
	while (remaining_len > 0) {
		struct hdr4_field hdr4_field;
		hdr4_field.tag = read_uint16(fd, buf);
		hdr4_field.len = read_uint16(fd, buf);
		remaining_len -= 2 * sizeof(uint16_t);

		printf("remaining header length: %d\n", remaining_len);

		printf(" header field - tag: 0x%02x, length: %d", hdr4_field.tag, hdr4_field.len);
		read_buf2(fd, buf, hdr4_field.len);
		if (hdr4_field.tag == 1) {
			uint32_t timestamps[2];
			memcpy(timestamps, buf->buf, sizeof(timestamps));
			timestamps[0] = be32toh(timestamps[0]);
			timestamps[1] = be32toh(timestamps[1]);

			printf("  kcd time offset: %u.%06u\n", timestamps[0], timestamps[1]);
		} else
			printf("  unknown field tag\n");

		remaining_len -= hdr4_field.len;
	}
	return 0;
}





struct principal *load_principal(int fd, struct buf_config *buf) {
	struct principal *principal = malloc(sizeof(struct principal));
	int i;

	principal->type = read_uint32(fd, buf);
	principal->count = read_uint32(fd, buf);

	principal->realm.len = read_uint32(fd, buf);
	read_buf2(fd, buf, principal->realm.len);
	principal->realm.value = memdup(buf->buf, principal->realm.len, true);

	principal->components = malloc(sizeof(struct data) * principal->count);

	for (i = 0 ; i < principal->count ; i++) {
		principal->components[i].len = read_uint32(fd, buf);
		read_buf2(fd, buf, principal->components[i].len);
		principal->components[i].value = memdup(buf->buf, principal->components[i].len, true);
	}

	return principal;
}

struct addresses *load_addresses(int fd, struct buf_config *buf) {
	struct addresses *addresses;
	uint32_t count;
	int i;

	count = read_uint32(fd, buf);
	addresses = malloc(sizeof(struct addresses) + count * sizeof(struct address));
	addresses->count = count;
	for (i = 0 ; i < count ; i++) {
		addresses->address[i].addrtype = read_uint16(fd, buf);
		addresses->address[i].data.len = read_uint32(fd, buf);
		addresses->address[i].data.value = read_data(fd, buf, addresses->address[i].data.len);
	}
	return addresses;
}
struct authdatas *load_authdatas(int fd, struct buf_config *buf) {
	struct authdatas *authdatas;
	uint32_t count;
	int i;

	count = read_uint32(fd, buf);
	authdatas = malloc(sizeof(struct authdatas) + count * sizeof(struct authdata));
	authdatas->count = count;
	for (i = 0 ; i < count ; i++) {
		authdatas->authdata[i].ad_type = read_uint16(fd, buf);
		authdatas->authdata[i].data.len = read_uint32(fd, buf);
		authdatas->authdata[i].data.value = read_data(fd, buf, authdatas->authdata[i].data.len);
	}
	return authdatas;
}

struct credential *load_credential(int fd, struct buf_config *buf) {
	struct credential *credential = malloc(sizeof(struct credential));

	credential->client = load_principal(fd, buf);
	credential->server = load_principal(fd, buf);

	// load keyblock
	credential->keyblock.enctype = read_uint16(fd, buf);
	credential->keyblock.data.len = read_uint32(fd, buf);
	credential->keyblock.data.value = read_data(fd, buf, credential->keyblock.data.len);

	credential->authtime = read_uint32(fd, buf);
	credential->starttime = read_uint32(fd, buf);
	credential->endtime = read_uint32(fd, buf);
	credential->renew_till = read_uint32(fd, buf);

	credential->is_skey = read_uint8(fd, buf);
	credential->ticket_flags = read_uint32(fd, buf);
	credential->addresses = load_addresses(fd, buf);
	credential->authdata = load_authdatas(fd, buf);

	credential->ticket.len = read_uint32(fd, buf);
	credential->ticket.value = read_data(fd, buf, credential->ticket.len);

	credential->second_ticket.len = read_uint32(fd, buf);
	credential->second_ticket.value = read_data(fd, buf, credential->second_ticket.len);

	return credential;
}

void show_keyblock(struct keyblock *keyblock) {
	printf("    keyblock enctype: %d (%s), length: %d\n",
		keyblock->enctype, enctype_str(keyblock->enctype), keyblock->data.len);
//	printf(" (data not output)\n");
	print_hexdump("    ", keyblock->data.value, keyblock->data.len);
}
void show_addresses(struct addresses *addresses) {
	printf("    %u addresses\n", addresses->count);
	// print the addresses?
}
void show_authdatas(struct authdatas *authdatas) {
	printf("    %u authdatas\n", authdatas->count);
	// print the authdatas?
}
void show_ticket(struct data *ticket) {
	print_hexdump("      ", ticket->value, ticket->len);
}
const char *principal_realm(const struct principal *principal) {
	return (char *)principal->realm.value;
}

bool is_config_cred(struct credential *credential) {
	const char *realm_str = principal_realm(credential->server);

	if (realm_str && !strcmp("X-CACHECONF:", realm_str) &&
		credential->server->count >= 2 &&
		credential->server->count <= 3 &&
		!strcmp("krb5_ccache_conf_data", (char *)credential->server->components[0].value))
		return true;
	return false;
}
void show_config_entry(struct credential *credential) {
	char *config_key = (char *)credential->server->components[1].value;

	printf("configuration entry: ");
	if (!strcmp("refresh_time", config_key)) {
		printf("refresh_time: %s\n", credential->ticket.value);
	} else if (!strcmp("fast_avail", config_key)) {
		printf("fast_avail: KDC asserted FAST support during initial authentication\n");
	} else {
		printf("unknown type: %s\n", config_key);
	}
}
void show_principal(struct principal *principal) {
	int i;

	printf("(%s) ", krb5_princ_type_str(principal->type));

	for (i = 0 ; i < principal->count ; i++)
		printf("%s%c", principal->components[i].value, i < principal->count - 1 ? '/' : '@');

	printf("%s\n", principal->realm.value);
}

void show_credential(struct credential *credential) {
	if (is_config_cred(credential)) {
		show_config_entry(credential);
	} else {
		printf("client principal: ");
		show_principal(credential->client);
		printf("server principal: ");
		show_principal(credential->server);
		show_keyblock(&credential->keyblock);

		printf("    authtime: %u", credential->authtime);
		printf("    starttime: %u", credential->starttime);
		printf("    endtime: %u", credential->endtime);
		printf("    renew_till: %u", credential->renew_till);
		printf("\n");

		printf("    skey: %d", credential->is_skey);
		printf(", ticket flags: %04x (%s)\n", credential->ticket_flags, flags_string(credential->ticket_flags));

		show_addresses(credential->addresses);
		show_authdatas(credential->authdata);

		printf("    ticket:\n");
		show_ticket(&credential->ticket);
		printf("    second ticket:\n");
		show_ticket(&credential->second_ticket);
	}
}

int load_file(int fd) {
	struct buf_config buf;
	int ret = EXIT_FAILURE;

	struct v4_hdr v4_hdr;

	buf.size = 0;
	buf.buf = NULL;

	// two-byte version indicator
	read_buf2(fd, &buf, 2);
	if (buf.buf[0] != 5) {
		printf("bad format... expected version 5, but got 0x%02x\n", buf.buf[0]);
		goto out;
	}
	if (buf.buf[1] != 4) {
		printf("bad format... expected file format 4, but got 0x%02x\n", buf.buf[1]);
		goto out;
	}

	read_show_header(fd, &buf);

	printf("default principal: ");
	struct principal *principal = load_principal(fd, &buf);
	show_principal(principal);


	while (!is_eof(fd)) {
		struct credential *credential;
		printf("\n");
//		printf("credential (file pos: %ld):\n", file_pos(fd));
		credential = load_credential(fd, &buf);
		show_credential(credential);
	}


	ret = EXIT_SUCCESS;

out:
	return ret;
}


int main(int argc, char *argv[]) {
	char *filename = argv[1];
	uint8_t *buf;
	int buf_size = 256;
	int fd, ret = EXIT_FAILURE;
	struct v4_hdr v4_hdr;
	int len;

	if (argc != 2) {
		printf("usage: %s <filename>\n", argv[0]);
		return EXIT_SUCCESS;
	}
	if ((fd = open(filename, O_RDONLY)) < 0) {
		printf("error opening %s: %m\n", filename);
		return EXIT_FAILURE;
	}

	load_file(fd);

	ret = EXIT_SUCCESS;
out:
	close(fd);
	return ret;
}

