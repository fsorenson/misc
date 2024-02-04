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

#define min(_a,_b) ({ typeof(_a) a = _a; typeof(_b) b = _b; a < b ? a : b; })

static int buf_size = DEFAULT_BUF_SIZE;
static char *path = ".";

#define CSI_CODE(seq)	"\33[" seq
#define CSI_SGR(x)	CSI_CODE(#x) "m"

#define ANSI_RESET      "\x1b[0m"
#define ANSI_BOLD_ON    "\x1b[1m"
#define ANSI_BOLD_OFF   "\x1b[22m"

#define ANSI_INVERSE_ON "\x1b[7m"

#define ANSI_FG_BLACK	"\x1b[30m"
#define ANSI_FG_RED	"\x1b[31m"
#define ANSI_FG_GREEN	"\x1b[32m"
#define ANSI_FG_YELLOW	"\x1b[33m"
#define ANSI_FG_BLUE	"\x1b[34m"
#define ANSI_FG_MAGENTA	"\x1b[35m"
#define ANSI_FG_CYAN	"\x1b[36m"
#define ANSI_FG_WHITE	"\x1b[37m"

#define ANSI_BG_BLACK	"\x1b[40m"
#define ANSI_BG_RED	"\x1b[41m"
#define ANSI_BG_GREEN	"\x1b[42m"
#define ANSI_BG_YELLOW	"\x1b[43m"
#define ANSI_BG_BLUE	"\x1b[44m"
#define ANSI_BG_MAGENTA	"\x1b[45m"
#define ANSI_BG_CYAN	"\x1b[46m"
#define ANSI_BG_WHITE	"\x1b[47m"



typedef enum { color_normal, color_ino, color_offset, color_reclen, color_type, color_name, color_filler, color_none } color_code;
char *color_code_colors[] = {
	[color_normal] = ANSI_RESET,
	[color_ino] = ANSI_FG_CYAN,
	[color_offset] = ANSI_FG_RED,
	[color_reclen] = ANSI_FG_BLUE,
	[color_type] = ANSI_FG_GREEN,
	[color_name] = ANSI_FG_YELLOW,
	[color_filler] = ANSI_FG_BLACK ANSI_BG_WHITE,
	[color_none] = ANSI_FG_BLACK ANSI_BG_BLACK,
};

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

static void dump_color_dirent(const char *addr, size_t entry_start) {
	struct dirent *de = (struct dirent *)addr;
	size_t dirent_offset = 0; // offset from start of current dirent
	char hexbuf[4096];
	char colorbuf[4096];

	int filler_len = 0;
	int namelen;
	int i;

	// fill the colorbuf
	memset(colorbuf, color_normal, sizeof(colorbuf));
// printf("entry_start: %ld\n", entry_start);
	for (i = 0 ; i < sizeof(de->d_ino) ; i++)
		colorbuf[dirent_offset++] = color_ino;

	for (i = 0 ; i < sizeof(de->d_off) ; i++)
		colorbuf[dirent_offset++] = color_offset;

	for (i = 0 ; i < sizeof(de->d_reclen) ; i++)
		colorbuf[dirent_offset++] = color_reclen;

	for (i = 0 ; i < sizeof(de->d_type) ; i++)
		colorbuf[dirent_offset++] = color_type;

	namelen = strlen(de->d_name);

	for (i = 0 ; i < namelen ; i++)
		colorbuf[dirent_offset++] = color_name;
	filler_len = de->d_reclen - dirent_offset;
	while (dirent_offset < de->d_reclen)
		colorbuf[dirent_offset++] = color_filler;

	memcpy(hexbuf, addr, de->d_reclen);

	dirent_offset = 0;
	while (dirent_offset < de->d_reclen) {
		int start_skip = min(16, (entry_start + dirent_offset) % 16);
		int output_bytes = min(16 - start_skip, de->d_reclen - dirent_offset);
		int end_skip = 16 - start_skip - output_bytes;

//		printf("at this dirent's offset of %ld:  start_skip: %d, output_bytes: %d, end_skip: %d\n",
//			dirent_offset, start_skip, output_bytes, end_skip);

		printf("%08lx  ", entry_start + dirent_offset - start_skip);

		for (i = 0 ; i < start_skip ; i++)
			printf("   ");
		if (start_skip >= 8)
			printf(" ");

		for (i = 0 ; i < output_bytes ; i++) {
			unsigned char ch = hexbuf[dirent_offset + i];
			printf("%s%02x%s ", color_code_colors[(int)colorbuf[dirent_offset + i]], ch, color_code_colors[color_normal]);
			if (start_skip + i == 7)
				printf(" ");
		}
		for (i = 0 ; i < end_skip ; i++) {
			printf("   ");
			if (start_skip + output_bytes + i == 7)
				printf(" ");
		}

		printf("|");
		for (i = 0 ; i < start_skip ; i++)
			printf(" ");
		for (i = 0 ; i < output_bytes ; i++) {
			unsigned char ch = hexbuf[dirent_offset + i];
			printf("%s", color_code_colors[(int)colorbuf[dirent_offset + i]]);
			if (isprint(ch))
				printf("%c", ch);
			else
				printf(".");
			printf("%s", color_code_colors[color_normal]);
		}
		printf("|");

		printf("\n");

		dirent_offset += output_bytes;
	}

	printf("  decoding of %d-byte dirent:\n", de->d_reclen);

	printf("   inode: %s%12lu%s (%ld bytes)\n", color_code_colors[color_ino], de->d_ino, color_code_colors[color_normal], sizeof(de->d_ino));
	printf("   offset of next entry: %s%ld%s (%ld bytes)\n", color_code_colors[color_offset], de->d_off, color_code_colors[color_normal], sizeof(de->d_off));
	printf("    reclen: %s%d%s bytes (%ld bytes)\n", color_code_colors[color_reclen], de->d_reclen, color_code_colors[color_normal], sizeof(de->d_reclen));
	printf("    type: %s%s%s (%ld bytes)\n", color_code_colors[color_type], stat_file_type_str(DTTOIF(de->d_type)), color_code_colors[color_normal], sizeof(de->d_type));
	printf("    entry name: %s%s%s (%d bytes)\n", color_code_colors[color_name], de->d_name, color_code_colors[color_normal], namelen);
	printf("    filler: %s%d bytes%s\n", color_code_colors[color_filler], filler_len, color_code_colors[color_normal]);

	printf("\n");
}

void call_getdents(void) {
	struct dirent *de;
	int dir_fd;
	char *bpos;
	char *buf;
	int nread, ret;;
	int entry_count = 0;
	int getdents_count= 0;
	unsigned long getdents_bytes = 0;

	printf("open(\"%s\", O_RDONLY | O_DIRECTORY)", path);
	dir_fd = open(path, O_RDONLY | O_DIRECTORY);
	printf(" = %d  (errno: %d - %m)\n", dir_fd, errno);
	if (dir_fd < 0) {
		printf("could not open directory '%s': %m\n", path);
		return;
	}

	buf = malloc(buf_size);
	while (42) {
		getdents_count++;
		printf("getdents64(dir_fd: %d, buf: %p, buf_size: %d)",
			dir_fd, buf, buf_size);
		nread = syscall(SYS_getdents64, dir_fd, buf, buf_size);
		printf(" = %d  (errno: %d - %m)\n", nread, errno);

		if (nread < 0) {
			printf("error caling getdents()\n");
			return;
		}

		getdents_bytes += nread;
		if (nread == 0) /* no more entries */
			break;

		bpos = buf; /* bpos is an iterator through the buffer */
		while (bpos < buf + nread) {
			printf("*** directory entry %d\n", ++entry_count);
			de = (struct dirent *)bpos; /* point de at the current location in the buffer */
			bpos += de->d_reclen; /* move the iterator to the next entry */

			dump_color_dirent((char *)de, (int)((char *)de - buf));
		}
	}
	printf("close(fd: %d)", dir_fd);
	ret = close(dir_fd);
	printf(" = %d  (errno: %d - %m)\n", ret, errno);
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
