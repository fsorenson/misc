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
#include <time.h>

#define BUF_LEN 4096

#define READ_SLEEP_TIME ((struct timespec){ .tv_sec = 0, .tv_nsec = 250000000 })
#define WRITE_SLEEP_TIME ((struct timespec){ .tv_sec = 0, .tv_nsec = 100000000 })

#define ARRAY_LEN(a) (sizeof(a)/sizeof(a[0]))

struct val_str_struct {
	int val;
	char *name;
};
#define V(f) { .val = f, .name = #f }

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

typedef enum run_type_enum {
	run_type_unknown,
	run_type_writer,
	run_type_reader_mmap,
	run_type_reader_read,
} run_type_t;

struct val_str_struct run_type_names[] = {
	V(run_type_unknown),
	V(run_type_writer),
	V(run_type_reader_mmap),
	V(run_type_reader_read),
};
char *get_runtype_str(run_type_t run_type) {
	int i;

	for (i = 0 ; i < (sizeof(run_type_names)/sizeof(run_type_names[0])) ; i++) {
		if (run_type == run_type_names[i].val)
			return run_type_names[i].name;
	}
	return "UNKNOWN";
}
struct run_config_struct;

typedef enum lock_mode_enum {
	lock_mode_never,
	lock_mode_test,
	lock_mode_lock_unlock,
} lock_mode_t;

typedef enum additional_open_fd_enum {
	additional_fd_none,
	additional_fd_ro,
	additional_fd_wo,
	additional_fd_rw,
} additional_open_fd_t;


struct run_config_struct {
	char *filename;
	run_type_t run_type;
	bool use_mmap;
	bool do_reopens;
	bool do_remaps;
	bool do_sleeps;

	lock_mode_t lock_mode;
	bool open_rw;
	bool locks_exclusive;

	bool grow_shrink; // write-side grow/shrink file

	bool open_direct;
	bool open_sync;
	bool open_dsync;

	additional_open_fd_t additional_fd_mode;
	int additional_fd;
	struct timespec sleep_time;

} run_config = {
	.run_type = run_type_reader_read,
//	.use_mmap = false,
	.do_reopens = false,
	.do_remaps = false,

	.lock_mode = lock_mode_never,
	.open_rw = false,
	.locks_exclusive = false,

	.open_direct = false,
	.open_sync = false,
	.open_dsync = false,

	.additional_fd_mode = additional_fd_none,
	.additional_fd = -1,

	.sleep_time = (struct timespec){ -1, -1 },
	.do_sleeps = true,
};


#define do_open(filename, open_flags...) ({ \
	int fd; \
	if ((fd = open(filename, open_flags)) < 0) { \
		output("failed to open file: %m\n"); \
		return EXIT_FAILURE; \
	} \
	fd; \
})

#define do_map(fd) ({ \
	void *_m; \
	if ((_m = (char *)mmap(0, BUF_LEN, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) { \
		output("failed to map: %m\n"); \
		goto out; \
	} \
	(char *)_m; \
})
#define do_unmap(map) do { munmap(map, BUF_LEN); } while (0)

#define do_read(fd, buf) do { \
	pread(fd, buf, BUF_LEN, 0); \
} while (0)

#define do_lock(fd) do { \
	fl_lock.l_type = run_config.locks_exclusive ? F_WRLCK : F_RDLCK; \
	if (fcntl(fd, F_SETLKW, &fl_lock) < 0) { \
		output("failed to set read lock: %m\n"); \
		goto out; \
	} \
} while (0)
#define do_unlock(fd) do { \
	if (fcntl(fd, F_SETLKW, &fl_unlock) < 0) { \
		output("failed to release read lock: %m\n"); \
		goto out; \
	} \
} while (0)
#define do_testlock(fd) do { \
	fl_lock.l_type = run_config.locks_exclusive ? F_WRLCK : F_RDLCK; \
	if (fcntl(fd, F_GETLK, &fl_lock) < 0) { \
		output("failed to test lock: %m\n"); \
		goto out; \
	} \
} while (0)
#define do_reopen() do { \
	int fd_tmp = open(filename, O_RDONLY); \
	close(fd_tmp); \
} while (0)

int do_read_runtype(void) {
	struct flock fl_lock = {
		.l_type = F_UNLCK,
		.l_start = 0,
		.l_whence = SEEK_SET,
		.l_len = 0,
	};
	struct flock fl_unlock = fl_lock;
	int fd, ret = EXIT_FAILURE;
	int open_flags = run_config.open_rw ? O_RDWR : O_RDONLY;
	char *map;

	if (run_config.sleep_time.tv_sec == -1 && run_config.sleep_time.tv_nsec == -1)
		run_config.sleep_time = READ_SLEEP_TIME;

	if (run_config.open_direct)
		open_flags |= O_DIRECT;
	if (run_config.open_sync)
		open_flags |= O_SYNC;
	if (run_config.open_dsync)
		open_flags |= O_DSYNC;

	if (run_config.additional_fd_mode != additional_fd_none) {
		int tmp_flags =
			run_config.additional_fd_mode == additional_fd_ro ? O_RDONLY :
			run_config.additional_fd_mode == additional_fd_wo ? O_WRONLY :
			O_RDWR;

		run_config.additional_fd = do_open(run_config.filename, tmp_flags);
	}

	output("starting as reader, with runtype '%s'\n", get_runtype_str(run_config.run_type));

	if (run_config.run_type == run_type_reader_read)
		map = malloc(BUF_LEN);

	if (!run_config.do_reopens) {
		fd = do_open(run_config.filename, open_flags);

		if (run_config.run_type == run_type_reader_mmap)
			map = do_map(fd);
	}

	while (42) {
		if (run_config.do_reopens)
			fd = do_open(run_config.filename, open_flags);

		if (run_config.lock_mode == lock_mode_test)
			do_testlock(fd);
		else if (run_config.lock_mode == lock_mode_lock_unlock)
			do_lock(fd);
		else { /* no syncronization */
		}

		if (run_config.run_type == run_type_reader_mmap && run_config.do_reopens)
			map = do_map(fd);
		else if (run_config.run_type == run_type_reader_read)
			do_read(fd, map);

		output("%c", map[0]);

		if (run_config.run_type == run_type_reader_mmap && run_config.do_reopens)
			do_unmap(map);

		if (run_config.lock_mode == lock_mode_lock_unlock)
			do_unlock(fd);

		if (run_config.do_reopens)
			close(fd);

		if (run_config.do_sleeps)
			nanosleep(&run_config.sleep_time, NULL);
	}
out:
	return ret;
}
const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
int do_write_runtype(void) {
	char *buf;
	int open_flags = O_CREAT | (run_config.open_rw ? O_RDWR : O_WRONLY);
	size_t current_file_size = BUF_LEN;
	int fd, char_num = 0;

	if (run_config.sleep_time.tv_sec == -1 && run_config.sleep_time.tv_nsec == -1)
		run_config.sleep_time = WRITE_SLEEP_TIME;

	if (run_config.open_direct)
		open_flags |= O_DIRECT;
	if (run_config.open_sync)
		open_flags |= O_SYNC;
	if (run_config.open_dsync)
		open_flags |= O_DSYNC;

	if (!run_config.do_reopens) {
		fd = do_open(run_config.filename, open_flags, 0666);
		ftruncate(fd, BUF_LEN);
	}

	output("starting as writer\n");

	buf = malloc(BUF_LEN * (run_config.grow_shrink + 1));
	while (42) {

		if (run_config.do_reopens)
			fd = do_open(run_config.filename, open_flags, 0666);

		if (run_config.grow_shrink) {
			current_file_size = BUF_LEN * ( (char_num % 2) + 1);
			ftruncate(fd, current_file_size);
		}
		memset(buf, chars[char_num], current_file_size);
		pwrite(fd, buf, current_file_size, 0);

		if (run_config.do_reopens)
			close(fd);

		output("%c", chars[char_num]);

		if (run_config.do_sleeps)
			nanosleep(&run_config.sleep_time, NULL);
		char_num = (char_num + 1) % (sizeof(chars)/sizeof(chars[0]));
	}
	return EXIT_FAILURE;
}

int usage(int argc, char *argv[], int ret) {
	output("usage: %s <run_type> <filename>\n", argv[0]);
	output("\twhere <run_type> is:\n");

	// mode should be writer, mmap, read

	output("\t\t--writer | --write - write to the file\n");
	output("\t\t--mmap - reader with mmap; use other options to specify any synchronization methods\n");
	output("\t\t--read - reader with read() syscall; use options to specify any synchronization methods\n");

#if 0
	output("\t\t--remap - reader with new mmap() each read; sync through new mmap()\n");
	output("\t\t--testlock | --test - reader, with read() syscall; only testing the lock\n");
#endif

	output("\n");
	output("\toptions:\n");


	output("\t\t--rw - open in read-write mode\n");
	output("\t\t\tdefault for write is write-only; default for a reader is read-only\n");
	output("\t\t\t(implied by some other options)\n");


	output("\n");
	output("\t\t--lock=<lock_behavior>\n");

	output("\t\t\tro | read | shared - take/release a read lock in the loop\n");
	output("\t\t\t\tdefault for a reader\n");
	output("\t\t\t\tnonsensical, but permitted for a writer (system may consider this invalid)\n");
	output("\t\t\t\tshortcut: --rlock\n");
	output("\n");

	output("\t\t\trw | wo | write | exclusive - take/release a write lock in the loop\n");
	output("\t\t\t\tdefault for a writer\n");
	output("\t\t\t\tfor a reader, implies opening the file in read-write mode\n");
	output("\t\t\t\tshortcut: --wlock\n");

	output("\t\t\ttest - only test the lock in the loop (readers only)\n");
	output("\t\t\t\tshortcut: --testlock\n");


	// --lock=(ro|read|shared)|(rw|wo|write|exclusive)|test


/*
	output("\t\t--lock - for writer, lock file for each write; for reader, lock file for each read\n");
	output("\t\t\tdefaults to write lock for writer, read lock for reader (change with options)\n");
	output("\t\t\talthough a read lock for a writer is bad programming practice\n");

	output("\n");
	output("\t\t[ --rlock | --wlock | --testlock ]  - mutually exclusive\n");
*/

	output("\n");
	output("\t\t-F <fd_mode> - open an additional fd at start time\n");
	output("\t\t\tro | wo | rw - open read-only, write-only, or read-write\n");


	output("\n");
	output("\t\t--sleep_time=<milliseconds>\n");
	output("\t\t\treader default: %lu milliseconds\n",
		((READ_SLEEP_TIME.tv_sec) * 1000) +
		(READ_SLEEP_TIME.tv_nsec / 1000000));
	output("\t\t\twriter default: %lu milliseconds\n",
		((WRITE_SLEEP_TIME.tv_sec) * 1000) +
		(WRITE_SLEEP_TIME.tv_nsec / 1000000));



	output("\n");
	output("\t\t-M | --remap - for mmap mode, unmap and map each time; invalid for write or read mode\n");

	output("\n");
	output("\t\t-R | --reopen - close and reopen the file each time while reading\n");
	output("\t\t\tfor mmap mode, also implies remap\n");

	output("\n");
	output("\t\t-d | --direct - open the file with O_DIRECT\n");
	output("\t\t-s | --sync - open the file with O_SYNC\n");
	output("\t\t-D | --dsync - open the file with O_DSYNC\n");


	return ret;
}

int match_lock_mode(const char *_mode) {
	typedef enum mode_enum {
		NOT_FOUND = 0,
		READ_MODE,
		WRITE_MODE,
		TEST_MODE,
	} mode_enum_t;
	struct val_str_struct lock_modes[] = {
		{ .val = READ_MODE, .name = "read" },
		{ .val = READ_MODE, .name = "ro" },
		{ .val = READ_MODE, .name = "shared" },
		{ .val = WRITE_MODE, .name = "write" },
		{ .val = WRITE_MODE, .name = "wo" },
		{ .val = WRITE_MODE, .name = "rw" },
		{ .val = WRITE_MODE, .name = "exclusive" },
	};
	mode_enum_t selected_mode = NOT_FOUND;
	int ret = EXIT_SUCCESS, i;

	for (i = 0 ; i < ARRAY_LEN(lock_modes) ; i++) {
		if (!strcmp(_mode, lock_modes[i].name)) {
			selected_mode = lock_modes[i].val;
			goto out_found;
		}
	}
out_found:
	switch (selected_mode) {
		case READ_MODE:
//			output("lock mode shared\n");
			run_config.lock_mode = lock_mode_lock_unlock;
			run_config.locks_exclusive = false;
			break;
		case WRITE_MODE:
//			output("lock mode exclusive\n");
			run_config.lock_mode = lock_mode_lock_unlock;
			run_config.locks_exclusive = true;
			run_config.open_rw = true;
			break;
		case TEST_MODE:
//			output("lock mode test\n");
			run_config.lock_mode = lock_mode_test;
			break;
		default:
			ret = EXIT_FAILURE;
			break;
	}
	return ret;
}


int main(int argc, char *argv[]) {
	static struct option long_options[] = {
		{ "writer", no_argument, NULL, 'w' },
		{ "write", no_argument, NULL, 'w' },
		{ "mmap", no_argument, NULL, 'm' },
		{ "reader", no_argument, NULL, 'r' },
		{ "read", no_argument, NULL, 'r' },

		{ "lock", optional_argument, NULL, 'l' },
		{ "locks", optional_argument, NULL, 'l' },
		{ "rlock", no_argument, NULL, 'R' },
		{ "wlock", no_argument, NULL, 'W' },
		{ "testlock", no_argument, NULL, 't' },



		{ "rw", no_argument, NULL, 'Z' },
		{ "remap", no_argument, NULL, 'M' },
		{ "reopen", no_argument, NULL, 'O' },

		{ "direct", no_argument, NULL, 'd' },
		{ "sync", no_argument, NULL, 's' },
		{ "dsync", no_argument, NULL, 'D' },

		{ "fd", required_argument, NULL, 'F' },

		{ "sleep_time", required_argument, NULL, 'S' },

		{ NULL, 0, NULL, 0 },
	};
	int opt, longoptind;

//	while ((opt = getopt_long(argc, argv, "wmMQrRoOtnWdsDh", long_options, &optind)) != -1) {
	while ((opt = getopt_long(argc, argv, "dDF:hl::mMOrRsS:twZ", long_options, &longoptind)) != -1) {
//		output("opt is '%c', optopt is '%c', optind is %d: '%s', longoptind is %d: '%s'\n", opt, optopt,
//			optind, argv[optind], longoptind, long_options[longoptind].name);
//		output("optind -1: '%s'\n", argv[optind - 1]);

		switch (opt) {
		// modes:  writer, mmap, read
			case 'w': run_config.run_type = run_type_writer; break;
			case 'm': run_config.run_type = run_type_reader_mmap; break;
			case 'r': run_config.run_type = run_type_reader_read; break;
			case 'M': run_config.do_remaps = true ; break; // does nothing unless run_type is mmap
			case 'O': run_config.do_reopens = true; break;

			case 'l': {

				if (strchr(argv[optind - 1], '=')) {
					output("embedded option?\n");
					char *optptr = optptr = strchr(argv[optind - 1], '=') + 1;
					if (match_lock_mode(optptr) != EXIT_SUCCESS) {
						output("unrecognized lock mode: '%s'\n", optptr);
						return usage(argc, argv, EXIT_FAILURE);
					}
//				} else if (argv[optind] == NULL) {
//					output("no filename provided\n");
//					return usage(argc, argv, EXIT_FAILURE);
//				} else {
				} else if (argv[optind] != NULL) {
					if (match_lock_mode(argv[optind]) == EXIT_SUCCESS)
						optind++;
				}
			}; break;
			case 'R': match_lock_mode("shared"); break;
			case 'W': match_lock_mode("exclusive"); break;
			case 't': match_lock_mode("test"); break;
			case 'Z': run_config.open_rw = true ; break;
			case 'F': {
//				printf("optarg: %p\n", optarg);
				if (!strcmp(optarg, "ro"))
					run_config.additional_fd_mode = additional_fd_ro;
				else if (!strcmp(optarg, "wo"))
					run_config.additional_fd_mode = additional_fd_wo;
				else if (!strcmp(optarg, "rw"))
					run_config.additional_fd_mode = additional_fd_rw;
				else {
					printf("unrecognized option '%s' for additional fd mode\n", optarg);
					return usage(argc, argv, EXIT_FAILURE);
				}
			}; break;
			case 'd': run_config.open_direct = true ; break;
			case 's': run_config.open_sync = true ; break;
			case 'D': run_config.open_dsync = true ; break;
			case 'S': {
				// in milliseconds
				unsigned long millis = strtoul(optarg, NULL, 10);
				run_config.sleep_time.tv_sec = millis / 1000;
				run_config.sleep_time.tv_nsec = (millis % 1000) * 1000000;
			}; break;
			case 'h': return usage(argc, argv, EXIT_SUCCESS);
			default:
				output("unknown argument: %c\n", opt);
				return usage(argc, argv, EXIT_FAILURE);
		}
	}
	if (run_config.run_type == run_type_unknown) {
		output("no run method specified\n");
		return usage(argc, argv, EXIT_FAILURE);
	}
	if (optind >= argc) {
		output("No file specified\n");
		return usage(argc, argv, EXIT_FAILURE);
	}
	run_config.filename = argv[optind];

	if (run_config.do_remaps && run_config.run_type == run_type_reader_read) {
		output("reader with read() syscall selected, but mmap remap option given.  Ignoring remap\n");
		run_config.do_remaps = false;
	}

	if (run_config.sleep_time.tv_sec == 0 && run_config.sleep_time.tv_nsec == 0)
		run_config.do_sleeps = false;

	output("using file: '%s'\n", run_config.filename);
	if (run_config.open_direct)
		output("opening file with O_DIRECT\n");
	if (run_config.open_sync)
		output("opening file with O_SYNC\n");
	if (run_config.open_dsync)
		output("opening file with O_DSYNC\n");
	if (run_config.run_type == run_type_writer)
		do_write_runtype();
	else
		do_read_runtype();

	return EXIT_FAILURE; /* this should be an infinite loop */
}
