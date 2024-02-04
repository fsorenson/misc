/*
	Frank Sorenson <sorenson@redhat.com>, 2021

	test_stale-5 - test program to reproduce an nfs server bug that results in
		the nfs client caching stale pages of a file if the client reads
		the file at the same time as the file is updated on the nfs
		server's local filesystem

		In particular, the nfs server returns the old file contents, but
		the updated file attributes/changeid

	# gcc test_stale-5.c -o test_stale-5


	execute on a single system:
		# mount 127.0.0.1:/exports /mnt/tmp
		# ./test_stale-5 /exports /mnt/tmp

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
//#include <sys/vfs.h>    /* or <sys/statfs.h> */
#include <linux/magic.h>
#include <sys/statfs.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>



#define ARRAY_LEN(a) (sizeof(a)/sizeof(a[0]))
#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define max(a,b) ({ \
	typeof(a) _a = a; \
	typeof(b)_b = b; \
	_a > _b ? _a : _b; \
})

#define ___PASTE(a,b)           a##b
#define ___PASTE3(a,b,c)        a##b##c

#define PASTE(a,b)            ___PASTE(a,b)
#define PASTE3(a,b,c)         ___PASTE3(a,b,c)

#define COMPILE_TIME_ASSERT(cond) \
	extern void compile_time_assert(int arg[(cond) ? 1 : -1])
#define mb()   asm volatile("mfence" ::: "memory")
#define nop()   __asm__ __volatile__ ("nop")
#define mb_nop() do { \
	register char i = 100; \
	while (i-- > 0) \
		nop(); \
	mb(); \
} while (0)
#define wait_for_state_cond(cond) do { \
	while (!(cond)) \
		mb_nop(); \
} while (0)

#define USEC_NS (1000)
#define MSEC_NS (USEC_NS * 1000)
#define BUF_SIZE (4096*4)

#define THREAD_WAIT_SLEEP_MS (10)

#define STALE_DATA_FILE "stale_data"

typedef enum run_state { run_state_pause, run_state_run, run_state_check_stale, run_state_exit } run_state_t;

typedef struct config_struct {
	char *exe;

	volatile run_state_t run_state;
	volatile char stale_read;
	volatile char stale_expected;
	uint64_t reader_iters;

	volatile char current_char;
	char *local_dir;
	char *remote_dir;
	int local_dfd;
	int remote_dfd;

} config_struct_t;
config_struct_t *config;

int usage(int ret) {
	output("usage:\n");
	output("         %s <local_directory> <remote_directory>\n", config->exe);
	output("\n");
	output("        these directories should refer to the same directory, one local and one remote\n");
	output("        within the directory, one file will be craeted during testing: '" STALE_DATA_FILE "'\n");

	return ret;
}

#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC 0x58465342
#endif

//const __fsword_t local_fs_magics[] = {
const __SWORD_TYPE local_fs_magics[] = {
	EXT4_SUPER_MAGIC,
	XFS_SUPER_MAGIC,
};
//const __fsword_t remote_fs_magics[] = {
const __SWORD_TYPE remote_fs_magics[] = {
	NFS_SUPER_MAGIC,
};
#define verify_valid_fs_magic(dfd, path, type) ({ \
	__label__ PASTE3(valid_, type, _magic); \
	int i, magics_count = ARRAY_LEN(PASTE(type, _fs_magics)); \
	fstatfs(dfd, &PASTE(type, _stfs)); \
	for (i = 0 ; i < magics_count ; i++) { \
		if (PASTE(type, _stfs).f_type == PASTE(type, _fs_magics)[i]) \
			goto PASTE3(valid_, type, _magic); \
	} \
	output("WARNING: path '%s' is not a valid %s filesystem\n", path, #type); \
PASTE3(valid_, type, _magic): \
	fstat(dfd, &PASTE(type, _st)); \
})


//const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const char chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
#define CHAR_COUNT ARRAY_LEN(chars)

const char spinner[] = "|/-\\|/-\\";
#define SPINNER_COUNT ARRAY_LEN(spinner)

void write_file_byte(int dfd, const char *path, char *filename, char *buf, char byte, bool open_direct) {
	int open_flags = O_RDWR | (open_direct ? O_DIRECT : 0);
	int fd;

//	memset(buf, byte, BUF_SIZE);
	buf[0] = byte;
	if ((fd = openat(dfd, filename, open_flags)) < 0) {
		output("error opening '%s/%s': %m\n", path, filename);
		exit(-1);
	}
	pwrite(fd, buf, BUF_SIZE, 0);
	close(fd);
	return;
}

bool directory_exists(const char *path) {
	struct stat st;
	if (stat(path, &st) != 0)
		return false;
	return (S_ISDIR(st.st_mode)) ? true : false;
}

int read_worker(void) {
	char expected_char, read_char;
	run_state_t current_run_state;
	uint64_t iter = 0;
	char *buf;
	int fd;

	posix_memalign((void **)&buf, 4096, BUF_SIZE);
	memset(buf, '\0', BUF_SIZE);
	buf[1] = '\n';

	while (42) {
		mb();
		current_run_state = config->run_state; // just read once per loop

		if (current_run_state == run_state_pause) {
			wait_for_state_cond(config->run_state != run_state_pause);
		} else if (current_run_state == run_state_run) {
			iter++;
			mb();
			expected_char = config->current_char;

			fd = openat(config->remote_dfd, STALE_DATA_FILE, O_RDONLY);
			pread(fd, buf, BUF_SIZE, 0);
			close(fd);
			read_char = buf[0];

			if (read_char != expected_char) {
				config->run_state = run_state_pause;
				mb();

				config->stale_expected = expected_char;
				config->stale_read = read_char;
				config->reader_iters = iter;
				config->run_state = run_state_check_stale;
				mb();
			}
		} else if (current_run_state == run_state_check_stale) {
			wait_for_state_cond(config->run_state != run_state_check_stale);
                } else if (current_run_state == run_state_exit)
			break;
		else
			output("unknown state: %d\n", current_run_state);
	}
	return EXIT_SUCCESS;
}
int write_worker(void) {
        struct timespec sleep_time = { .tv_sec = 0, .tv_nsec = (100 * MSEC_NS) };
	run_state_t current_run_state;
	int spinner_num = 0;
	uint64_t iter = 0;
	int char_num = 0;
	char *buf;
	int write_fd;

        posix_memalign((void **)&buf, 4096, BUF_SIZE);
        memset(buf, '\0', BUF_SIZE);
	buf[1] = '\n';

//	write_file_byte(config->local_dfd, config->local_dir, STALE_DATA_FILE, buf, chars[char_num], true);

	config->run_state = run_state_run;

	write_fd = openat(config->local_dfd, STALE_DATA_FILE, O_RDWR|O_SYNC);
	pwrite(write_fd, buf, BUF_SIZE, 0);

	while (42) {
		config->current_char = chars[char_num];
		mb();
		current_run_state = config->run_state; // just read once per loop

		if (current_run_state == run_state_pause) {
			wait_for_state_cond(current_run_state != run_state_pause);
		} else if (current_run_state == run_state_run) {
			iter++;
			output("\r%c", spinner[spinner_num]);
			spinner_num = (spinner_num + 1) % SPINNER_COUNT;

//			memset(buf, chars[char_num], BUF_SIZE);
//			memset(buf, chars[char_num], BUF_SIZE);
			buf[0] = chars[char_num];
			pwrite(write_fd, buf, BUF_SIZE, 0);
			fsync(write_fd);
			char_num = (char_num + 1) % CHAR_COUNT;

			nanosleep(&sleep_time, NULL);
		} else if (current_run_state == run_state_check_stale) {
			char direct_char, read_char;

			output("\rpossible stale found: ");
			output("expected '%c', but found '%c'\n",
				config->stale_expected, config->stale_read);

			/* verify that nfs has cached old data */
			int test_fd = openat(config->remote_dfd, STALE_DATA_FILE, O_RDONLY|O_DIRECT);
			pread(test_fd, buf, BUF_SIZE, 0);
			close(test_fd);
			direct_char = buf[0];

			test_fd = openat(config->remote_dfd, STALE_DATA_FILE, O_RDONLY);
			pread(test_fd, buf, BUF_SIZE, 0);
			close(test_fd);
			read_char = buf[0];

			if (direct_char != read_char) {
				output(" -- confirmed stale data: file has '%c', but returns cached '%c'\n",
					direct_char, read_char);
				output("completed after %" PRIu64 " reader iterations and %" PRIu64 " writer iterations\n",
					config->reader_iters, iter);
				config->run_state = run_state_exit;
				mb();
			} else {
				output(" -- false alarm; cached char: %c, direct char: %c\n", read_char, direct_char);
				config->run_state = run_state_run;
				mb();
			}
		} else if (current_run_state == run_state_exit)
			break;
		else
			output("unknown state: %d\n", current_run_state);
	}
	return EXIT_SUCCESS;
}

int start_workers(void) {
	pid_t cpid;
	struct statfs local_stfs, remote_stfs;
	struct stat local_st, remote_st;
	int fd;

	output("%s starting in single-system mode\n", config->exe);

	if ((config->local_dfd = open(config->local_dir, O_RDONLY|O_DIRECTORY)) < 0) {
		output("error opening local directory '%s': %m\n", config->local_dir);
		return usage(EXIT_FAILURE);
	}
	verify_valid_fs_magic(config->local_dfd, config->local_dir, local);

	if ((config->remote_dfd = open(config->remote_dir, O_RDONLY|O_DIRECTORY)) < 0) {
		output("error opening nfs directory '%s': %m\n", config->remote_dir);
		return usage(EXIT_FAILURE);
	}
	verify_valid_fs_magic(config->remote_dfd, config->remote_dir, remote);
//	if (memcmp(&local_stfs.f_fsid, &remote_stfs.f_fsid, sizeof(struct statfs)) || local_st.st_ino != remote_st.st_ino) {
	if (local_st.st_ino != remote_st.st_ino) {
		output("WARNING: '%s' and '%s' do not appear to refer to the same directory (%ld vs %ld)\n",
			config->local_dir, config->remote_dir, local_st.st_ino, remote_st.st_ino);
//		return usage(EXIT_FAILURE);
	}

	unlinkat(config->local_dfd, STALE_DATA_FILE, 0);
	if ((fd = openat(config->local_dfd, STALE_DATA_FILE, O_RDWR|O_CREAT|O_TRUNC|O_DIRECT, 0644)) < 0) {
		output("unable to open test file '%s/%s': %m\n", config->local_dir, STALE_DATA_FILE);
		return usage(EXIT_FAILURE);
	}

	ftruncate(fd, BUF_SIZE);
	posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
	close(fd);

	if ((fd = openat(config->remote_dfd, STALE_DATA_FILE, O_RDONLY)) < 0) {
		output("unable to open test file '%s/%s': %m\n", config->remote_dir, STALE_DATA_FILE);
		return usage(EXIT_FAILURE);
	}
	posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED); // start with a clean slate
	close(fd);

	config->current_char = chars[0];
	config->run_state = run_state_pause;
	mb();

	if ((cpid = fork()) == 0)
		return write_worker();
	else
		return read_worker();
}

int main(int argc, char *argv[]) {
	config = mmap(NULL, sizeof(config), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	config->exe = strdup(argv[0]);

	if (argc != 3)
		return usage(EXIT_FAILURE);

	if (!directory_exists(argv[1])) {
		output("unable to open directory '%s'\n", argv[1]);
		return usage(EXIT_FAILURE);
	}

	if (directory_exists(argv[2])) {
		config->local_dir = strdup(argv[1]);
		config->remote_dir = strdup(argv[2]);
		return start_workers();
	} else
		return usage(EXIT_FAILURE);

	return EXIT_FAILURE;
}
