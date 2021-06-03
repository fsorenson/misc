/*
	Frank Sorenson <sorenson@redhat.com>, 2021

	demonstration program for bug where existing
	mmap() continues to return stale data after
	a file lock causes the inode to be marked
	NFS_INODE_INVALID_DATA

	# gcc test_file_coherence.c -o test_file_coherence -g


*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <getopt.h>

#define MAP_LEN 4096

struct val_str_struct {
	int val;
	char *name;
};
#define V(f) { .val = f, .name = #f }

typedef enum run_type_enum {
	run_type_writer,
	run_type_reader_mmap,
	run_type_reader_mmap_nosync,
	run_type_reader_mmap_open,
	run_type_reader_mmap_direct,
	run_type_reader_newmmap,
	run_type_reader_read,
	run_type_reader_read_nosync,
	run_type_reader_read_open,
	run_type_reader_testlock
} run_type_t;

struct val_str_struct run_type_names[] = {
	V(run_type_writer),
	V(run_type_reader_mmap),
	V(run_type_reader_mmap_nosync),
	V(run_type_reader_mmap_open),
	V(run_type_reader_mmap_direct),
	V(run_type_reader_newmmap),
	V(run_type_reader_read),
	V(run_type_reader_read_nosync),
	V(run_type_reader_read_open),
	V(run_type_reader_testlock),
};
char *get_runtype_str(run_type_t run_type) {
	int i;

	for (i = 0 ; i < (sizeof(run_type_names)/sizeof(run_type_names[0])) ; i++) {
		if (run_type == run_type_names[i].val)
			return run_type_names[i].name;
	}
	return "UNKNOWN";
}

#define do_map(fd) ({ \
	void *_m; \
	if ((_m = (char *)mmap(0, MAP_LEN, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) { \
		printf("failed to map: %m\n"); \
		goto out; \
	} \
	(char *)_m; \
})
#define do_read(fd, buf) do { \
	lseek(fd, 0, SEEK_SET); \
	read(fd, buf, MAP_LEN); \
} while (0)
#define do_lock(fd) do { \
	if (fcntl(fd, F_SETLKW, &fl_lock) < 0) { \
		printf("failed to set read lock: %m\n"); \
		goto out; \
	} \
} while (0)
#define do_unlock(fd) do { \
	if (fcntl(fd, F_SETLKW, &fl_unlock) < 0) { \
		printf("failed to release read lock: %m\n"); \
		goto out; \
	} \
} while (0)
#define do_testlock(fd) do { \
	fl_lock.l_type = F_RDLCK; \
	if (fcntl(fd, F_GETLK, &fl_lock) < 0) { \
		printf("failed to test lock: %m\n"); \
		goto out; \
	} \
} while (0)
#define do_reopen() do { \
	int fd_tmp = open(filename, O_RDONLY); \
	close(fd_tmp); \
} while (0)

int do_read_runtype(run_type_t run_type, const char *filename) {
	bool use_mmap = false,
		do_remaps = false,
		do_reads = false,
		do_reopens = false,
		lock_unlock = false,
		test_lock = false;
	struct flock fl_lock = {
		.l_type = F_RDLCK,
		.l_start = 0,
		.l_whence = SEEK_SET,
		.l_len = 0,
	};
	struct flock fl_unlock = fl_lock;
	fl_unlock.l_type = F_UNLCK;
	int fd, ret = EXIT_FAILURE;
	int open_flags = O_RDONLY;
	char *map;

	if (run_type == run_type_reader_mmap) {
		use_mmap = true; lock_unlock = true;
	} else if (run_type == run_type_reader_mmap_direct) {
		use_mmap = true; lock_unlock = true;
		open_flags |= O_DIRECT|O_SYNC;
	} else if (run_type == run_type_reader_mmap_nosync) {
		use_mmap = true;
	} else if (run_type == run_type_reader_mmap_open) {
		use_mmap = true; do_reopens = true;
	} else if (run_type == run_type_reader_newmmap) {
//		use_mmap = true; lock_unlock = true;
		do_remaps = true; lock_unlock = true;
	} else if (run_type == run_type_reader_read) {
		do_reads = true; lock_unlock = true;
	} else if (run_type == run_type_reader_read_nosync) {
		do_reads = true;
	} else if (run_type == run_type_reader_read_open) {
		do_reads = true ; do_reopens = true;
	} else if (run_type == run_type_reader_testlock) {
		do_reads = true; test_lock = true;
	}

	if ((fd = open(filename, open_flags)) < 0) {
		printf("failed to open read-only: %m\n");
		return EXIT_FAILURE;
	}

	printf("starting as reader, with runtype '%s'\n", get_runtype_str(run_type));
	fflush(stdout);

	if (use_mmap)
		map = do_map(fd);
	else if (do_reads)
		map = malloc(MAP_LEN);

	while (42) {
		if (do_reopens)
			do_reopen();
		else if (test_lock)
			do_testlock(fd);
		else if (lock_unlock)
			do_lock(fd);
		else { /* no syncronization */
		}

		if (do_remaps)
			map = do_map(fd);
		else if (do_reads)
			do_read(fd, map);

		printf("%c", map[0]);
		fflush(stdout);

		if (do_remaps)
			munmap(map, MAP_LEN);

		if (lock_unlock)
			do_unlock(fd);

		usleep(250000);
	}

out:
	return ret;
}
const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
int do_write_runtype(char *filename) {
	char *buf;
	int fd, i = 0;


	if ((fd = open(filename, O_CREAT|O_RDWR, 0666)) < 0) {
		printf("failed to open read-write: %m\n");
		return EXIT_FAILURE;
	}
	ftruncate(fd, MAP_LEN);

	printf("starting as writer\n");
	fflush(stdout);

	buf = malloc(MAP_LEN);
	while (42) {
		memset(buf, chars[i], MAP_LEN);
		lseek(fd, 0, SEEK_SET);
		write(fd, buf, MAP_LEN);
		fsync(fd);
		printf("%c", chars[i]);
		fflush(stdout);

		usleep(100000);
		i = (i + 1) % (sizeof(chars)/sizeof(chars[0]));
	}
	return EXIT_FAILURE;
}

int usage(int argc, char *argv[], int ret) {
	printf("usage: %s <run_type> <filename>\n", argv[0]);
	printf("\twhere <run_type> is:\n");
	printf("\t\t--writer | --write - write to the file\n");
	printf("\t\t--mmap - reader with mmap; sync using locking\n");
	printf("\t\t--mmap_nosync - reader with mmap(); no locking or other synchronization\n");
	printf("\t\t--mmap_open - reader with mmap(); sync using open()close() of the file\n");
	printf("\t\t--mmap_direct - reader with mmap, using O_DIRECT; sync using locking\n");
	printf("\t\t--remap - reader with new mmap() each read; sync through new mmap()\n");
	printf("\t\t--read - reader with read() syscall; sync using locking\n");
	printf("\t\t--read_nosync - reader with read() syscall; sync using locking\n");
	printf("\t\t--read_open - reader with read() syscall; sync using open()/close() of the file\n");
	printf("\t\t--testlock | --test - reader, with read() syscall; only testing the lock\n");

	return ret;
}
int main(int argc, char *argv[]) {
	static struct option long_options[] = {
		{ "writer", no_argument, NULL, 'w' },
		{ "write", no_argument, NULL, 'w' },
		{ "mmap", no_argument, NULL, 'm' },
		{ "mmap_nosync", no_argument, NULL, 'M' },
		{ "mmap_open", no_argument, NULL, 'O' },
		{ "mmap_direct", no_argument, NULL, 'd' },
		{ "remap", no_argument, NULL, 'Q' },
		{ "read", no_argument, NULL, 'r' },
		{ "read_nosync", no_argument, NULL, 'R' },
		{ "read_open", no_argument, NULL, 'o' },
		{ "testlock", no_argument, NULL, 't' },
		{ "test", no_argument, NULL, 't' },
		{ NULL, 0, NULL, 0 },
	};
	char *filename = NULL;
	run_type_t runtype = run_type_reader_mmap;
	int opt;

	while ((opt = getopt_long(argc, argv, "wmMdQrRoOtnh", long_options, &optind)) != -1) {
		switch (opt) {
			case 'w': runtype = run_type_writer; break;
			case 'm': runtype = run_type_reader_mmap; break;
			case 'M': runtype = run_type_reader_mmap_nosync; break;
			case 'O': runtype = run_type_reader_mmap_open; break;
			case 'd': runtype = run_type_reader_mmap_direct; break;
			case 'Q': runtype = run_type_reader_newmmap; break;
			case 'r': runtype = run_type_reader_read; break;
			case 'R': runtype = run_type_reader_read_nosync; break;
			case 'o': runtype = run_type_reader_read_open; break;
			case 't': runtype = run_type_reader_testlock; break;
			case 'h': return usage(argc, argv, EXIT_SUCCESS);
			default:
				printf("unknown argument: %c\n", opt);
				return usage(argc, argv, EXIT_FAILURE);
		}
	}
	if (optind >= argc) {
		printf("No file specified\n");
		return usage(argc, argv, EXIT_FAILURE);
	}
	filename = argv[optind];

	printf("using file: '%s'\n", filename);
	if (runtype == run_type_writer)
		do_write_runtype(filename);
	else
		do_read_runtype(runtype, filename);

	return EXIT_FAILURE; /* this should be an infinite loop */
}
