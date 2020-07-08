/*

	Frank Sorenson <sorenson@redhat.com>, 2019
*/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

//#define _USE_GNU

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <getopt.h>

#include <sys/syscall.h>
#include <errno.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE     00100000
#endif

#define KiB (1024ULL)
#define MiB (KiB * KiB)

#define DEFAULT_BUF_SIZE (32ULL * KiB)
#define MIN_BUF_SIZE (10)


#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

static int buf_size = DEFAULT_BUF_SIZE;
static char *path = ".";

#define ANSI_RESET      "\x1b[0m"
#define ANSI_BOLD_ON    "\x1b[1m"
#define ANSI_BOLD_OFF   "\x1b[22m"

#define ANSI_INVERSE_ON "\x1b[7m"

#define ANSI_FG_BLACK   "\x1b[30m"
#define ANSI_FG_RED     "\x1b[31m"
#define ANSI_FG_GREEN   "\x1b[32m"
#define ANSI_FG_YELLOW  "\x1b[33m"
#define ANSI_FG_BLUE    "\x1b[34m"
#define ANSI_FG_MAGENTA "\x1b[35m"
#define ANSI_FG_CYAN    "\x1b[36m"
#define ANSI_FG_WHITE   "\x1b[37m"

#define ANSI_BG_RED     "\x1b[41m"
#define ANSI_BG_GREEN   "\x1b[42m"
#define ANSI_BG_YELLOW  "\x1b[43m"
#define ANSI_BG_BLUE    "\x1b[44m"
#define ANSI_BG_MAGENTA "\x1b[45m"
#define ANSI_BG_CYAN    "\x1b[46m"
#define ANSI_BG_WHITE   "\x1b[47m"

void dump_dirent(void) {
	struct dirent de;

//	struct linux_dirent de2;
//	printf("other size: %lu\n", sizeof(de2));

	printf("linux_dirent size = %d\n", (int)sizeof(de));
	printf("\td_ino: offset=%d, size=%d\n", (int)offsetof(typeof(de), d_ino), (int)sizeof(de.d_ino));
	printf("\td_off: offset=%d, size=%d\n", (int)offsetof(typeof(de), d_off), (int)sizeof(de.d_off));
	printf("\td_reclen: offset=%d, size=%d\n", (int)offsetof(typeof(de), d_reclen), (int)sizeof(de.d_reclen));
	printf("\td_type: offset=%d, size=%d\n", (int)offsetof(typeof(de), d_type), (int)sizeof(de.d_type));
	printf("\td_name: offset=%d, size=%d\n", (int)offsetof(typeof(de), d_name), (int)sizeof(de.d_name));

}

long int get_buf_size(char *size) {
	long int buf_size = (-1);
	char *ptr;

	buf_size = strtoul(size, &ptr, 10);
	switch (ptr[0]) {
		case 'G' :
		case 'g' :
			buf_size *= 1024;
		case 'M' :
		case 'm' :
			buf_size *= 1024;
		case 'K' :
		case 'k' :
			buf_size *= 1024;
		default  :
			break;
	}
	return buf_size;
}

char *stat_file_type_str(int t) {
	char *type;

	switch (t & S_IFMT) {
		case S_IFBLK: type = "BLK"; break;
		case S_IFCHR: type = "CHR"; break;
		case S_IFDIR: type = "DIR"; break;
		case S_IFIFO: type = "FIFO"; break;
		case S_IFLNK: type = "LINK"; break;
		case S_IFSOCK: type = "SOCK"; break;
		case S_IFREG: type = "REG"; break;
		default: type = "ERROR"; break;
	}
	return type;
}

static void hexdump(const char *pre, size_t buf_offset, const char *addr, size_t len) {
	size_t offset = 0;
	char buf[17];
	int i;

	while (offset < len) {
		int this_count = len - offset;
		if (this_count > 16)
		this_count = 16;

		memcpy(buf, addr + offset, this_count);
		printf("%s0x%08" PRIx32 ": ", pre, (uint32_t)(buf_offset + offset));
		for (i = 0 ; i < 16 ; i++) {
			if (i < this_count)
				printf("%02x ", buf[i] & 0xff);
			else
				printf("   ");
			if (i == 7)
				printf("| ");
			if (i >= this_count)
				buf[i] = '\0';
			else if (! isprint(buf[i] & 0xff))
				buf[i] = '.';
		}
		buf[i] = '\0';
		printf(" |%s|\n", buf);
		offset += this_count;
	}
}

enum hexdump_output_flags {
	OUTPUT_NORMAL = 0,
	OUTPUT_FLUSH_ONLY,
	OUTPUT_FLUSH_AFTER,
	OUTPUT_RESET,
};

void hexdump_output_add_char(const unsigned char ch, const char *color_code, int flag) {
	static char output_buf[256] = [ '\0' ];
	static int current_offset = 0;
	static int output_buf_len = 0;

	if (flag == OUTPUT_FLUSH_ONLY) {
		if (current_offset % 16 == 0)
			return;



	if (current_offset % 16 == 0) {
		printf("  0x%08" PRIx32 ": ", (uint32_t)current_offset);
		output_buf_len = 0;
		output_buf[0] = 0;
	}


				02" PRIx32 " ", (uint32_t)
				addr[current_offset] & 0xff);




static void dump_color_dirent(const char *addr, size_t entry_start) {
	struct dirent *de = (struct dirent *)addr;
	size_t end_offset = entry_start + de->d_reclen;
	size_t current_offset = entry_start;
	char hexbuf[128];
	int hexbuf_len = 0;
	int this_count;
	int i;

	printf("(" ANSI_FG_CYAN "%3d" ANSI_RESET " bytes) ", de->d_reclen);
	printf(ANSI_FG_GREEN "%s" ANSI_RESET "; ", stat_file_type_str(DTTOIF(de->d_type)));
	printf("inode " ANSI_FG_RED "%12lu" ANSI_RESET ": ", de->d_ino);
	printf(ANSI_INVERSE_ON "%s" ANSI_RESET, de->d_name);
	printf("\n");

	printf(" offset of next entry: " ANSI_FG_YELLOW "%lu" ANSI_RESET "\n", de->d_off);


	printf("    0x%08" PRIx32 ": ", (uint32_t)current_offset);
	printf(ANSI_FG_RED);
	hexbuf_len += snprintf(hexbuf, sizeof(hexbuf) - hexbuf_len, "%s", ANSI_FG_RED);
	for (current_offset = 0 ; current_offset < sizeof(de->d_ino) ; current_offset++) {
		printf("%02" PRIx32 " ", (uint32_t)addr[current_offset] & 0xff);

		if (isprint(addr[current_offset] & 0xff))
			hexbuf[hexbuf_len++] = addr[current_offset];
		else
			hexbuf[hexbuf_len++] = '.';
		hexbuf[hexbuf_len] = '\0';
	}
	hexbuf_len += snprintf(hexbuf + hexbuf_len, sizeof(hexbuf) - hexbuf_len, "%s", ANSI_RESET);

	if (current_offset == 8)
		printf(" | ");

	printf(ANSI_FG_YELLOW);
	hexbuf_len += snprintf(hexbuf + hexbuf_len, sizeof(hexbuf) - hexbuf_len, "%s", ANSI_FG_YELLOW);
	for ( ; current_offset < sizeof(de->d_ino) + sizeof(de->d_off) ; current_offset++) {
		printf("%02" PRIx32 " ", (uint32_t)addr[current_offset] & 0xff);
		if (isprint(addr[current_offset] & 0xff))
			hexbuf[hexbuf_len++] = addr[current_offset];
		else
			hexbuf[hexbuf_len++] = '.';
		hexbuf[hexbuf_len] = '\0';
	}
	printf(ANSI_RESET);
	hexbuf_len += snprintf(hexbuf + hexbuf_len, sizeof(hexbuf) - hexbuf_len, "%s", ANSI_RESET);

/*
	printf(ANSI_FG_RED "%02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx" ANSI_RESET,
		 de->d_ino & 0xff, (de->d_ino >> 8) & 0xff, (de->d_ino >> 16) & 0xff, (de->d_ino >> 24) & 0xff,
		 (de->d_ino >> 32) & 0xff, (de->d_ino >> 40) & 0xff, (de->d_ino >> 48) & 0xff, (de->d_ino >> 56) & 0xff);

	d_ino: offset=0, size=8
	d_off: offset=8, size=8
	d_reclen: offset=16, size=2
	d_type: offset=18, size=1

	hexbuf_len += snprintf(hexbuf + hexbuf_len, sizeof(hexbuf) - hexbuf_len, "%s", ANSI_RESET);

	printf(" | ");
	printf(ANSI_FG_YELLOW "%02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx" ANSI_RESET,
		de->d_off & 0xff, (de->d_off >> 8) & 0xff, (de->d_off >> 16) & 0xff, (de->d_off >> 24) & 0xff,
		(de->d_off >> 32) & 0xff, (de->d_off >> 40) & 0xff, (de->d_off >> 48) & 0xff, (de->d_off >> 56) & 0xff);

	hexbuf_len += snprintf(hexbuf + hexbuf_len, sizeof(hexbuf) - hexbuf_len, "%s", ANSI_FG_YELLOW);
	for (current_offset = 8 ; current_offset < 16 ; current_offset++) {
		if (isprint(addr[current_offset] & 0xff))
			hexbuf[hexbuf_len++] = addr[current_offset];
		else
			hexbuf[hexbuf_len++] = '.';
		hexbuf[hexbuf_len] = '\0';
	}
	hexbuf_len += snprintf(hexbuf + hexbuf_len, sizeof(hexbuf) - hexbuf_len, "%s", ANSI_RESET);

	if (hexbuf_len >= 16) {
	printf("  [%s]", hexbuf);

	printf("\n");
*/

	if (current_offset >= 16) {
		printf("  |%s|", hexbuf);
		hexbuf_len = 0;
		printf("\n");
	}


	printf("    0x%08" PRIx32 ": ", (uint32_t)current_offset);
	printf(ANSI_FG_CYAN "%02x %02x" ANSI_RESET, de->d_reclen & 0xff, (de->d_reclen >> 8) & 0xff);
	current_offset += 2;

	printf(" " ANSI_FG_GREEN "%02x" ANSI_RESET, de->d_type & 0xff);
	current_offset += 1;

	printf(" " ANSI_INVERSE_ON "%s" ANSI_RESET, de->d_name);
/*

	this_count = 3;
	while (current_offset < end_offset) {
		int this_count = end_offset - current_offset;
		if (this_count > 16)

*/

/*
	while (offset < len) {
		int this_count = len - offset;
		if (this_count > 16)
			this_count = 16;

		memcpy(buf, addr + offset, this_count);
		printf("%s0x%08lx: ", pre, buf_offset + offset);
		for (i = 0 ; i < 16 ; i++) {
			if (i < this_count)
				printf("%02x ", buf[i] & 0xff);
			else
				printf("   ");
			if (i == 7)
				printf("| ");
			if (i >= this_count)
				buf[i] = '\0';
			else if (! isprint(buf[i] & 0xff))
				buf[i] = '.';
		}
		buf[i] = '\0';
		printf(" |%s|\n", buf);
		offset += this_count;
	}
*/











	printf(ANSI_RESET "\n");
/*
linux_dirent size = 280
	d_ino: offset=0, size=8
	d_off: offset=8, size=8
	d_reclen: offset=16, size=2
	d_type: offset=18, size=1
	d_name: offset=19, size=256


			"%s0x%08lx: "

	printf("\td_ino: offset=%d, size=%d\n", (int)offsetof(typeof(de), d_ino), sizeof(de.d_ino));
	printf("\td_off: offset=%d, size=%d\n", (int)offsetof(typeof(de), d_off), sizeof(de.d_off));
	printf("\td_reclen: offset=%d, size=%d\n", (int)offsetof(typeof(de), d_reclen), sizeof(de.d_reclen));
	printf("\td_type: offset=%d, size=%d\n", (int)offsetof(typeof(de), d_type), sizeof(de.d_type));
	printf("\td_name: offset=%d, size=%d\n", (int)offsetof(typeof(de), d_name), sizeof(de.d_name));
*/
/*
			printf("(%3d bytes) %4s; inode %12lu: %s\n", de->d_reclen,
				stat_file_type_str(DTTOIF(de->d_type)), de->d_ino,
				de->d_name);
			hexdump("    ", (char *)de - buf, (char *)de, de->d_reclen);
*/

}




void call_getdents(void) {
	struct dirent *de;
	int dir_fd;
	char *bpos;
	char *buf;
	int nread;
	int entry_count = 0;
	int getdents_count= 0;
	unsigned long getdents_bytes = 0;

	if ((dir_fd = open(path, O_RDONLY | O_DIRECTORY)) == -1) {
		printf("could not open directory '%s': %m\n", path);
		return;
	}

	buf = malloc(buf_size);
	while (42) {
		getdents_count++;
		if ((nread = syscall(SYS_getdents64, dir_fd, buf, buf_size)) < 0) {
			printf("error caling getdents(): %m\n");
			return;
		}
		getdents_bytes += nread;
		if (nread == 0) /* no more entries */
			break;

		printf("getdents returned %d bytes\n", nread);
		hexdump("", 0, buf, nread);

		bpos = buf; /* bpos is an iterator through the buffer */
		while (bpos < buf + nread) {
			entry_count++;
			de = (struct dirent *)bpos; /* point de at the current location in the buffer */
			bpos += de->d_reclen; /* move the iterator to the next entry */

			printf("(%3d bytes) %4s; inode %12lu: %s\n", de->d_reclen,
				stat_file_type_str(DTTOIF(de->d_type)), de->d_ino,
				de->d_name);
			dump_color_dirent((char *)de, (int)((char *)de - buf));
			hexdump("    ", (char *)de - buf, (char *)de, de->d_reclen);
		}
	}
	close(dir_fd);
	printf("%d directory entries returned from %d getdents() calls; total bytes returned: %lu\n",
		entry_count, getdents_count, getdents_bytes);
}
int usage(char *argv0, int ret) {
	printf("Usage: %s [<path>] | [--help | -h ] [ --bufsize=<size> | -b <size> ]\n", argv0);
	return ret;
}

int parse_args(int argc, char *argv[]) {
	static struct option long_options[] = {
		{ "help",       no_argument,            NULL, 'h' },
		{ "bufsize",	required_argument,	NULL, 'b' },
//		{ "nonblock",   no_argument,            NULL, 'n' },
//		{ "sleep",      required_argument,      NULL, 's' },
	};
	char *ptr;
	int opt;

	while (42) {
		opt = getopt_long(argc, argv, "hb:", long_options, &optind);
		if (opt == -1)
			break;
		switch (opt) {
			case 'b':
				ptr = optarg ? optarg : argv[optind];
				buf_size = get_buf_size(ptr);
				if (buf_size < MIN_BUF_SIZE) {
					printf("buffer size must be at least %d bytes\n", MIN_BUF_SIZE);
					return EXIT_FAILURE;
				}
				break;
			case 'h':
			default:
				return EXIT_FAILURE;
				break;
		}
	}

	if (optind == argc - 1)
		path = strdup(argv[optind]);
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
	int ret;

	if ((ret = parse_args(argc, argv)) != EXIT_SUCCESS) {
		return usage(argv[0], EXIT_FAILURE);
	}

	dump_dirent();
	call_getdents();

	return EXIT_SUCCESS;
}
