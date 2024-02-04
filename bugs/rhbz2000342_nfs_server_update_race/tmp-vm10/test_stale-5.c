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

	or on the nfs server and another nfs client
		(*write* thread must run on the nfs server local filesystem)

		<server> # ./test_stale-5 /exports write

		<client> # mount server:/exports /mnt/tmp
		<client> # ./test_stale-5 /mnt/tmp read

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
#define BUF_SIZE (4096*1024)

#define THREAD_WAIT_SLEEP_MS (10)

#define STALE_CONTROL_FILE "stale_control"
#define STALE_DATA_FILE "stale_data"

// control file:
// bytes 0-63 - unused
// bytes 64-127 - run_lock_r - contains just '\0's
//     'reader' locks exclusively when running
//     'writer' tests shared lock to determine when 'reader' is running
// bytes 128-191 - run_lock_w - contains just '\0's
//     'writer' locks exclusively when running
//     'reader' tests shared lock to determine when 'writer' is running
#define LOCK_LEN		64
#define READER_LOCK_OFFSET	(LOCK_LEN)
#define WRITER_LOCK_OFFSET	(LOCK_LEN * 2)


typedef enum read_write_mode { READ_MODE, WRITE_MODE, SINGLE_SYSTEM } read_write_mode_t;
typedef enum run_state { run_state_pause, run_state_run, run_state_check_stale, run_state_exit } run_state_t;

typedef struct config_struct {
	read_write_mode_t run_mode;
	char *exe;
} config_struct_t;
config_struct_t *config;

typedef struct split_config_struct {
	int dfd;
	int control_fd;
	int fd;
	uint64_t iter;

	char *buf;
	char *basedir;

	int file_open_flags;
	struct flock our_run_lock;
	struct flock their_run_lock;
	char *our_name;
	char *their_name;
} split_config_struct_t;
split_config_struct_t *split_config;

typedef struct single_config_struct {
	volatile run_state_t run_state;
	volatile char stale_read;
	volatile char stale_expected;
	uint64_t reader_iters;

	volatile char current_char;
	char *local_dir;
	char *remote_dir;
	int local_dfd;
	int remote_dfd;
} single_config_struct_t;
single_config_struct_t *single_config;

int usage(int ret) {
	output("usage:\n");
	output("    multi-system mode:\n");
	output("        %s <local_directory> write\n", config->exe);
	output("        or\n");
	output("        %s <remote_directory> read\n", config->exe);
	output("\n");
	output("        these directories should refer to the same directory, one local and one remote\n");
	output("        within the directory, two files will be created during testing: '" STALE_CONTROL_FILE "' and '" STALE_DATA_FILE "'\n");
	output("\n");

	output("    single-system mode:\n");
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




bool other_thread_running(void) {
	split_config->their_run_lock.l_type = F_RDLCK;
	fcntl(split_config->control_fd, F_GETLK, &split_config->their_run_lock);

	return (split_config->their_run_lock.l_type == F_UNLCK) ? false : true;
}
void set_run_lock(void) {
        split_config->our_run_lock.l_type = F_WRLCK;
	fcntl(split_config->control_fd, F_SETLKW, &split_config->our_run_lock);
}
void release_run_lock(void) {
        split_config->our_run_lock.l_type = F_UNLCK;
	fcntl(split_config->control_fd, F_SETLKW, &split_config->our_run_lock);
}

void wait_other_thread(void) {
	static bool reported_online = false;
	bool reported_offline = false;

	while (!other_thread_running()) {
		if (!reported_offline) {
			output("\r'%s' waiting for '%s' to come online",
				split_config->our_name, split_config->their_name);
			if (split_config->iter > 0)
				output(" after %" PRIu64 " %s iterations", split_config->iter, split_config->our_name);
			output("\n");
			reported_offline = true;
			reported_online = false;
		}
		usleep(THREAD_WAIT_SLEEP_MS);
	}
	if (!reported_online) {
		output("\r'%s' is online\n", split_config->their_name);
		reported_online = true;
		reported_offline = false;
		split_config->iter = 0;
	}

}
char read_file_byte(int dfd, const char *path, const char *filename, char *buf, bool open_direct) {
	int open_flags = O_RDONLY | (open_direct ? O_DIRECT : 0);
	int fd;

	if ((fd = openat(dfd, filename, open_flags)) < 0) {
		output("error opening '%s/%s': %m\n", path, filename);
		exit(-1);
	}
	pread(fd, buf, BUF_SIZE, 0);
	close(fd);
	return buf[0];
}
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


int run_mode_split_read(void) {
	char *buf = split_config->buf, this_char, actual_char;
	struct timespec sleep_time;
	struct statfs remote_stfs;
	struct stat remote_st;
	int spinner_num = 0;

	split_config->our_name = "reader";
	split_config->their_name = "writer";
	sleep_time.tv_sec = 0; sleep_time.tv_nsec = 50*MSEC_NS;

	split_config->file_open_flags = O_RDONLY;

	split_config->our_run_lock.l_start = READER_LOCK_OFFSET;
	split_config->their_run_lock.l_start = WRITER_LOCK_OFFSET;

	output("%s starting as '%s'\n", config->exe, split_config->our_name);
	verify_valid_fs_magic(split_config->dfd, split_config->basedir, remote);

	posix_memalign((void **)&buf, 4096, BUF_SIZE);
	memset(buf, '\0', BUF_SIZE);
	buf[1] = '\n';
reopen_control:
	if ((split_config->control_fd = openat(split_config->dfd, STALE_CONTROL_FILE, O_RDWR|O_DIRECT)) < 0) {
		if (errno == ENOENT) {
			output("waiting for '%s' to create control file\n", split_config->their_name);
			sleep(1);
			goto reopen_control;
		}
		output("unable to open control file '%s/%s': %m\n", split_config->basedir, STALE_CONTROL_FILE);
		return usage(EXIT_FAILURE);
	}
	ftruncate(split_config->control_fd, BUF_SIZE); // in case the writer hasn't already
	set_run_lock(); // lock our run_lock to indicate we're running

	// flush all cached data for the file
	while (42) {
		if ((split_config->fd = openat(split_config->dfd, STALE_DATA_FILE, split_config->file_open_flags, 0644)) < 0) {
			if (errno == ENOENT) {
				sleep(1);
				continue;
			} else {
				output("could not open '%s/%s': %m\n", split_config->basedir, STALE_DATA_FILE);
				return usage(EXIT_FAILURE);
			}
		} else {
			posix_fadvise(split_config->fd, 0, 0, POSIX_FADV_DONTNEED);
			close(split_config->fd);
			break;
		}
	}

	while (42) {
restart_loop:
		wait_other_thread();
		split_config->iter++;

		this_char = read_file_byte(split_config->dfd, split_config->basedir, STALE_DATA_FILE, buf, false);
		if (this_char == '\0')
			goto restart_loop;

		actual_char = read_file_byte(split_config->dfd, split_config->basedir, STALE_DATA_FILE, buf, true);
		if (this_char != actual_char) {
			release_run_lock(); // unlock ourself to pause the writer

			nanosleep(&sleep_time, NULL);
			// double-check
			this_char = read_file_byte(split_config->dfd, split_config->basedir, STALE_DATA_FILE, buf, false);
			actual_char = read_file_byte(split_config->dfd, split_config->basedir, STALE_DATA_FILE, buf, true);
			if (this_char != actual_char) {
				output("\rfound stale data: expected '%c', but found '%c'\n",
					actual_char, this_char);
				output("completed after %" PRIu64 " reader iterations\n", split_config->iter);
				return EXIT_SUCCESS;
			}
			set_run_lock(); // false alarm... relock and continue
			continue;
		}

		
		output("\r%c - %c", spinner[spinner_num], actual_char);
		spinner_num = (spinner_num + 1) % SPINNER_COUNT;
		nanosleep(&sleep_time, NULL);
	}
	return EXIT_SUCCESS;
}

int run_mode_split_write(void) {
	struct timespec sleep_time;
	char *buf = split_config->buf;
	int spinner_num = 0, char_num = 0;
	struct statfs local_stfs;
	struct stat local_st;

	split_config->our_name = "writer";
	split_config->their_name = "reader";
	sleep_time.tv_sec = 0; sleep_time.tv_nsec = 500*MSEC_NS;

	split_config->file_open_flags = O_RDWR | O_CREAT | O_DIRECT;

	split_config->our_run_lock.l_start = WRITER_LOCK_OFFSET;
	split_config->their_run_lock.l_start = READER_LOCK_OFFSET;

	output("%s starting as '%s'\n", config->exe, split_config->our_name);
	verify_valid_fs_magic(split_config->dfd, split_config->basedir, local);

	posix_memalign((void **)&buf, 4096, BUF_SIZE);
	memset(buf, '\0', BUF_SIZE);
	buf[1] = '\n';

//	if ((split_config->control_fd = openat(split_config->dfd, STALE_CONTROL_FILE, O_RDWR|O_CREAT|O_TRUNC|O_DIRECT, 0644)) < 0) {
	if ((split_config->control_fd = openat(split_config->dfd, STALE_CONTROL_FILE, O_RDWR|O_CREAT|O_TRUNC, 0644)) < 0) {
		output("unable to open control file '%s/%s': %m\n", split_config->basedir, STALE_CONTROL_FILE);
		return usage(EXIT_FAILURE);
	}

	ftruncate(split_config->control_fd, BUF_SIZE);
	pwrite(split_config->control_fd, buf, BUF_SIZE, 0);

	set_run_lock(); // take our run_lock to indicate we're running

	if ((split_config->fd = openat(split_config->dfd, STALE_DATA_FILE, split_config->file_open_flags, 0644)) < 0) {
		output("could not create/open '%s/%s': %m\n", split_config->basedir, STALE_DATA_FILE);
		return usage(EXIT_FAILURE);
	}

	while (42) {
		buf[0] = chars[char_num];

		wait_other_thread();
		split_config->iter++;

		output("\r%c - %c", spinner[spinner_num], chars[char_num]);
		spinner_num = (spinner_num + 1) % SPINNER_COUNT;

		pwrite(split_config->fd, buf, BUF_SIZE, 0);

		nanosleep(&sleep_time, NULL);
		char_num = (char_num + 1) % CHAR_COUNT;
	}
	return EXIT_SUCCESS;
}

int run_mode_split(void) {
	split_config->iter = 0;
	split_config->our_run_lock.l_len = split_config->their_run_lock.l_len = LOCK_LEN;
	split_config->our_run_lock.l_whence = split_config->their_run_lock.l_whence = SEEK_SET;
	split_config->our_run_lock.l_type = F_WRLCK;
	split_config->their_run_lock.l_type = F_RDLCK;

	posix_memalign((void **)&split_config->buf, 4096, BUF_SIZE);
	memset(split_config->buf, '\0', BUF_SIZE);

	if ((split_config->dfd = open(split_config->basedir, O_RDONLY|O_DIRECTORY)) < 0) {
		output("unable to open directory '%s': %m\n", split_config->basedir);
		return usage(EXIT_FAILURE);
	}

	if (config->run_mode == READ_MODE)
		return run_mode_split_read();
	return run_mode_split_write();
}
int run_mode_single_read(void) {
	struct timespec sleep_time = { .tv_sec = 0, .tv_nsec = (30 * MSEC_NS) };
	char expected_char, read_char;
	run_state_t current_run_state;
	uint64_t iter = 0;
	char *buf;

	posix_memalign((void **)&buf, 4096, BUF_SIZE);
	memset(buf, '\0', BUF_SIZE);
	buf[1] = '\n';

	while (42) {
		mb();
		current_run_state = single_config->run_state; // just read once per loop

		if (current_run_state == run_state_pause) {
			wait_for_state_cond(single_config->run_state != run_state_pause);
		} else if (current_run_state == run_state_run) {
			iter++;
			mb();
			expected_char = single_config->current_char;
			read_char = read_file_byte(single_config->remote_dfd, single_config->remote_dir, STALE_DATA_FILE, buf, false);
			mb();

			if (read_char != expected_char) {
				single_config->run_state = run_state_pause;
				mb();

				single_config->stale_expected = expected_char;
				single_config->stale_read = read_char;
				single_config->reader_iters = iter;
				single_config->run_state = run_state_check_stale;
				mb();
			} else
				nanosleep(&sleep_time, NULL);
		} else if (current_run_state == run_state_check_stale) {
			wait_for_state_cond(single_config->run_state != run_state_check_stale);
                } else if (current_run_state == run_state_exit)
			break;
		else
			output("unknown state: %d\n", current_run_state);
	}
	return EXIT_SUCCESS;
}
int run_mode_single_write(void) {
        struct timespec sleep_time = { .tv_sec = 0, .tv_nsec = (500 * MSEC_NS) };
	run_state_t current_run_state;
	int spinner_num = 0;
	uint64_t iter = 0;
	int char_num = 0;
	char *buf;

        posix_memalign((void **)&buf, 4096, BUF_SIZE);
        memset(buf, '\0', BUF_SIZE);
	buf[1] = '\n';

	write_file_byte(single_config->local_dfd, single_config->local_dir, STALE_DATA_FILE, buf, chars[char_num], true);
	single_config->run_state = run_state_run;

	int fd = openat(single_config->local_dfd, STALE_DATA_FILE, O_RDWR|O_DIRECT|O_SYNC);
	while (42) {
		single_config->current_char = chars[char_num];
		mb();
		current_run_state = single_config->run_state; // just read once per loop

		if (current_run_state == run_state_pause) {
			wait_for_state_cond(current_run_state != run_state_pause);
		} else if (current_run_state == run_state_run) {
			iter++;
			output("\r%c", spinner[spinner_num]);
			spinner_num = (spinner_num + 1) % SPINNER_COUNT;

//			memset(buf, chars[char_num], BUF_SIZE);
//			memset(buf, chars[char_num], BUF_SIZE);
			buf[0] = chars[char_num];
			pwrite(fd, buf, BUF_SIZE, 0);
			char_num = (char_num + 1) % CHAR_COUNT;

			nanosleep(&sleep_time, NULL);
		} else if (current_run_state == run_state_check_stale) {
			char direct_char, read_char;

			output("\rpossible stale found: ");
			output("expected '%c', but found '%c'\n",
				single_config->stale_expected, single_config->stale_read);

			direct_char = read_file_byte(single_config->remote_dfd, single_config->remote_dir, STALE_DATA_FILE, buf, true);
			read_char = read_file_byte(single_config->remote_dfd, single_config->remote_dir, STALE_DATA_FILE, buf, false);

			if (direct_char != read_char) {
				output(" -- confirmed stale data: file has '%c', but returns cached '%c'\n",
					direct_char, read_char);
				output("completed after %" PRIu64 " reader iterations and %" PRIu64 " writer iterations\n",
					single_config->reader_iters, iter);
				single_config->run_state = run_state_exit;
				mb();
			} else {
				output(" -- false alarm\n");
				single_config->run_state = run_state_run;
				mb();
			}
		} else if (current_run_state == run_state_exit)
			break;
		else
			output("unknown state: %d\n", current_run_state);
	}
	return EXIT_SUCCESS;
}

int run_mode_single(void) {
	pid_t cpid;
	struct statfs local_stfs, remote_stfs;
	struct stat local_st, remote_st;
	int fd;

	output("%s starting in single-system mode\n", config->exe);

	if ((single_config->local_dfd = open(single_config->local_dir, O_RDONLY|O_DIRECTORY)) < 0) {
		output("error opening local directory '%s': %m\n", single_config->local_dir);
		return usage(EXIT_FAILURE);
	}
	verify_valid_fs_magic(single_config->local_dfd, single_config->local_dir, local);

	if ((single_config->remote_dfd = open(single_config->remote_dir, O_RDONLY|O_DIRECTORY)) < 0) {
		output("error opening nfs directory '%s': %m\n", single_config->remote_dir);
		return usage(EXIT_FAILURE);
	}
	verify_valid_fs_magic(single_config->remote_dfd, single_config->remote_dir, remote);
//	if (memcmp(&local_stfs.f_fsid, &remote_stfs.f_fsid, sizeof(struct statfs)) || local_st.st_ino != remote_st.st_ino) {
	if (local_st.st_ino != remote_st.st_ino) {
		output("WARNING: '%s' and '%s' do not appear to refer to the same directory (%ld vs %ld)\n",
			single_config->local_dir, single_config->remote_dir, local_st.st_ino, remote_st.st_ino);
//		return usage(EXIT_FAILURE);
	}

	unlinkat(single_config->local_dfd, STALE_DATA_FILE, 0);
	if ((fd = openat(single_config->local_dfd, STALE_DATA_FILE, O_RDWR|O_CREAT|O_TRUNC|O_DIRECT, 0644)) < 0) {
		output("unable to open test file '%s/%s': %m\n", single_config->local_dir, STALE_DATA_FILE);
		return usage(EXIT_FAILURE);
	}

	ftruncate(fd, BUF_SIZE);
	posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
	close(fd);

	if ((fd = openat(single_config->remote_dfd, STALE_DATA_FILE, O_RDONLY)) < 0) {
		output("unable to open test file '%s/%s': %m\n", single_config->remote_dir, STALE_DATA_FILE);
		return usage(EXIT_FAILURE);
	}
	posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED); // start with a clean slate
	close(fd);

	single_config->current_char = chars[0];
	single_config->run_state = run_state_pause;
	mb();

	if ((cpid = fork()) == 0)
		return run_mode_single_write();
	else
		return run_mode_single_read();
}

int main(int argc, char *argv[]) {
	config = malloc(sizeof(config_struct_t));

	config->exe = strdup(argv[0]);

	if (argc != 3)
		return usage(EXIT_FAILURE);

	if (!directory_exists(argv[1])) {
		output("unable to open directory '%s'\n", argv[1]);
		return usage(EXIT_FAILURE);
	}

	if (!strcmp(argv[2], "read")) {
		config->run_mode = READ_MODE;
		split_config = malloc(sizeof(split_config_struct_t));

		split_config->basedir = strdup(argv[1]);
		return run_mode_split();
	} else if (!strcmp(argv[2], "write")) {
		config->run_mode = WRITE_MODE;
		split_config = malloc(sizeof(split_config_struct_t));

		split_config->basedir = strdup(argv[1]);
		return run_mode_split();
	} else if (directory_exists(argv[2])) {
		config->run_mode = SINGLE_SYSTEM;

		single_config = mmap(NULL, sizeof(single_config_struct_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		single_config->local_dir = strdup(argv[1]);
		single_config->remote_dir = strdup(argv[2]);
		return run_mode_single();
	} else
		return usage(EXIT_FAILURE);

	return EXIT_FAILURE;
}
