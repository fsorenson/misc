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
		printf("getdents(\"%s\", %08" PRIx64 ", %d) returned %d bytes\n",
			path, (uint64_t)buf, buf_size, nread);

		if (nread == 0) /* no more entries */
			break;

		getdents_bytes += nread;
		hexdump("    ", 0, buf, nread);

		bpos = buf; /* bpos is an iterator through the buffer */
		while (bpos < buf + nread) {
			entry_count++;
			de = (struct dirent *)bpos; /* point de at the current location in the buffer */
			bpos += de->d_reclen; /* move the iterator to the next entry */

			printf("    (%3d bytes) type: %4s (%02x); inode %12lu: %s\n", de->d_reclen,
				stat_file_type_str(DTTOIF(de->d_type)), de->d_type,
				de->d_ino, de->d_name);
			printf("        offset to next entry: %lu\n", de->d_off);
			hexdump("      ", (char *)de - buf, (char *)de, de->d_reclen);
		}
	}
	close(dir_fd);

	printf("\n");
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
