#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>


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
#define BUF_SIZE 4096

// control file:
// bytes 0-63 - control_lock - status information from 'reader' to 'writer'
//     'reader' locks exclusive to write to this area, unlocks when not writing
//     'writer' locks shared to read from this area, unlocks when not readinga
// bytes 64-127 - run_lock_r - contains just '\0's
//     'reader' locks exclusively when running
//     'writer' tests shared lock to determine when 'reader' is running
// bytes 128-191 - run_lock_w - contains just '\0's
//     'writer' locks exclusively when running
//     'reader' tests shared lock to determine when 'writer' is running
#define LOCK_LEN		64
#define CONTROL_OFFSET		0
#define CONTROL_READER_OFFSET	(LOCK_LEN)
#define CONTROL_WRITER_OFFSET	(LOCK_LEN * 2)


//const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const char chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
#define CHAR_COUNT (sizeof(chars)/sizeof(chars[0]))

const char spinner[] = "|/-\\|/-\\";
#define SPINNER_LEN (sizeof(spinner)/sizeof(spinner[0]))

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define max(a,b) ({ \
	typeof(a) _a = a; \
	typeof(b)_b = b; \
	_a > _b ? _a : _b; \
})

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

	char *buf;
	char *basedir;

	int file_open_flags;
//	struct flock control_lock;
	struct flock our_run_lock;
	struct flock their_run_lock;
	char *our_name;
	char *their_name;
} split_config_struct_t;
split_config_struct_t *split_config;

typedef struct single_config_struct {
	volatile run_state_t run_state;
	volatile char stale_read;
	volatile char stale_expected1;
	volatile char stale_expected2;

	volatile char current_char;
	char *local_dir;
	char *nfs_dir;
	int local_dfd;
	int nfs_dfd;
} single_config_struct_t;
single_config_struct_t *single_config;

typedef struct new_config_struct {
	read_write_mode_t run_mode;
	char *exe;

	union {
		struct { // split config
			int dfd;
			int control_fd;
			int fd;

			char *buf;
			char *basedir;

			int file_open_flags;
		//	struct flock control_lock;
			struct flock our_run_lock;
			struct flock their_run_lock;
			char *our_name;
			char *their_name;
		};
		struct { // single-system run
			volatile run_state_t run_state;
			volatile char stale_read;
			volatile char stale_expected1;
			volatile char stale_expected2;

			volatile char current_char;
			char *local_dir;
			char *nfs_dir;
			int local_dfd;
			int nfs_dfd;
		};
	};
} new_config_struct_t;
new_config_struct_t *new_config;



const char *lock_type_to_str(short type) {
	if (type == F_RDLCK)
		return "F_RDLCK";
	if (type == F_WRLCK)
		return "F_WRLCK";
	if (type == F_UNLCK)
		return "F_UNLCK";
	return "UNKNOWN LOCK TYPE";
}


/*
bool is_running(int fd, const flock *fl) {
	fl->l_type = F_RDLCK;
	fcntl(fd, F_GETLK, fl);
	return (fl->l_type == F_UNLCK) ? false : true;
}
*/
bool other_thread_running(void) {
	split_config->their_run_lock.l_type = F_RDLCK;
	fcntl(split_config->control_fd, F_GETLK, &split_config->their_run_lock);

	return (split_config->their_run_lock.l_type == F_UNLCK) ? false : true;
}

void set_run_lock(void) {
	split_config->our_run_lock.l_type = F_WRLCK;
	if (config->run_mode == READ_MODE) {
		split_config->our_run_lock.l_start = CONTROL_READER_OFFSET;
		split_config->their_run_lock.l_start = CONTROL_WRITER_OFFSET;
	} else {
		split_config->our_run_lock.l_start = CONTROL_WRITER_OFFSET;
		split_config->their_run_lock.l_start = CONTROL_READER_OFFSET;

	}
	fcntl(split_config->control_fd, F_SETLKW, &split_config->our_run_lock);
}

void wait_other_thread(void) {
	static bool reported_online = false;
	bool reported_offline = false;

	while (!other_thread_running()) {
		if (!reported_offline) {
			output("waiting for '%s' to come online\n", split_config->their_name);
			reported_offline = true;
			reported_online = false;
		}
		usleep(10000);
	}
	if (!reported_online) {
		output("'%s' is online\n", split_config->their_name);
		reported_online = true;
		reported_offline = false;
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

	memset(buf, byte, BUF_SIZE);
	if ((fd = openat(dfd, filename, open_flags)) < 0) {
		output("error opening '%s/%s': %m\n", path, filename);
		exit(-1);
	}
	pwrite(fd, buf, BUF_SIZE, 0);
	close(fd);
	return;
}

int usage(int ret) {
	output("usage:\n");
	output("    multi-system mode: %s <base_directory> <read | write>\n", config->exe);
	output("        within the directory, two files will be created during testing: 'control' and 'testfile'\n");
	output("    single-system mode: %s <local_directory> <nfs_directory>\n", config->exe);
	output("        within the directory, one file will be craeted during testing: 'testfile'\n");

	return ret;
}
bool directory_exists(const char *path) {
	struct stat st;
	if (stat(path, &st) != 0)
		return false;
	return (S_ISDIR(st.st_mode)) ? true : false;
}


int run_mode_split_read(void) {
	char this_char;
	char actual_char1, actual_char2;
	struct timespec sleep_time;

	split_config->our_name = "reader";
	split_config->their_name = "writer";
	sleep_time.tv_sec = 0; sleep_time.tv_nsec = 50*MSEC_NS;

	split_config->file_open_flags = O_RDONLY;


	split_config->our_run_lock.l_len = split_config->their_run_lock.l_len = LOCK_LEN;
	split_config->our_run_lock.l_whence = split_config->their_run_lock.l_whence = SEEK_SET;
	split_config->our_run_lock.l_type = F_WRLCK;
	split_config->their_run_lock.l_type = F_RDLCK;

	if ((split_config->dfd = open(split_config->basedir, O_RDONLY|O_DIRECTORY)) < 0) {
		output("unable to open directory '%s': %m\n", split_config->basedir);
		return usage(EXIT_FAILURE);
	}

	posix_memalign((void **)&split_config->buf, 4096, BUF_SIZE);
	memset(split_config->buf, '\0', BUF_SIZE);
reopen_control:
	if ((split_config->control_fd = openat(split_config->dfd, "control", O_RDWR|O_DIRECT)) < 0) {
		if (errno == ENOENT) {
			output("waiting for '%s' to create control file\n", split_config->their_name);
			sleep(1);
			goto reopen_control;
		}
		output("unable to open control file '%s/%s': %m\n", split_config->basedir, "control");
		return usage(EXIT_FAILURE);
	}
	// lock our run_lock to indicate we're running
	set_run_lock();

	// flush all cached data for the file
	while (42) {
		if ((split_config->fd = openat(split_config->dfd, "testfile", split_config->file_open_flags, 0644)) < 0) {
			if (errno == ENOENT) {
				sleep(1);
				continue;
			} else {
				output("could not open '%s/%s': %m\n", split_config->basedir, "testfile");
				return usage(EXIT_FAILURE);
			}
		} else {
			posix_fadvise(split_config->fd, 0, 0, POSIX_FADV_DONTNEED);
			close(split_config->fd);
			break;
		}
	}

	while (42) {
//		output("%c\r", spinner[spinner_num]);
//		spinner_num= (spinner_num + 1) % (sizeof(spinner)/sizeof(spinner[0]));

restart_loop:
		wait_other_thread();

		actual_char1 = read_file_byte(split_config->dfd, split_config->basedir, "testfile", split_config->buf, true);

		if (actual_char1 == '\0')
			goto restart_loop;

		this_char = read_file_byte(split_config->dfd, split_config->basedir, "testfile", split_config->buf, false);
		if (this_char == '\0')
			goto restart_loop;

		actual_char2 = read_file_byte(split_config->dfd, split_config->basedir, "testfile", split_config->buf, true);
		if (this_char != actual_char1 && this_char != actual_char2) {
			if (actual_char1 == actual_char2) {
				output("found stale data: expected '%c', but found '%c'\n",
					actual_char1, this_char);
			} else {
				output("found stale data: expected either '%c' or '%c', but found '%c'\n",
					actual_char1, actual_char2, this_char);
			}
			return EXIT_SUCCESS;
		}

		nanosleep(&sleep_time, NULL);
	}
	return EXIT_SUCCESS;
}

int run_mode_split_write(void) {
	struct timespec sleep_time;
	int char_num = 0;

	split_config->our_name = "writer";
	split_config->their_name = "reader";
	sleep_time.tv_sec = 0; sleep_time.tv_nsec = 500*MSEC_NS;

	split_config->file_open_flags = O_RDWR | O_CREAT;

	split_config->our_run_lock.l_len = split_config->their_run_lock.l_len = LOCK_LEN;
	split_config->our_run_lock.l_whence = split_config->their_run_lock.l_whence = SEEK_SET;
	split_config->our_run_lock.l_type = F_WRLCK;
	split_config->their_run_lock.l_type = F_RDLCK;

	if ((split_config->dfd = open(split_config->basedir, O_RDONLY|O_DIRECTORY)) < 0) {
		output("unable to open directory '%s': %m\n", split_config->basedir);
		return usage(EXIT_FAILURE);
	}

	posix_memalign((void **)&split_config->buf, 4096, BUF_SIZE);
	memset(split_config->buf, '\0', BUF_SIZE);
	if ((split_config->control_fd = openat(split_config->dfd, "control", O_RDWR|O_CREAT|O_TRUNC|O_DIRECT, 0644)) < 0) {
		output("unable to open control file '%s/%s': %m\n", split_config->basedir, "control");
		return usage(EXIT_FAILURE);
	}

	/* do these outside our run_lock */
	ftruncate(split_config->control_fd, BUF_SIZE);
	pwrite(split_config->control_fd, split_config->buf, BUF_SIZE, 0);

	// lock our run_lock to indicate we're running
	set_run_lock();

	// flush all cached data for the file
	while (42) {
		if ((split_config->fd = openat(split_config->dfd, "testfile", split_config->file_open_flags, 0644)) < 0) {
			output("could not create/open '%s/%s': %m\n", split_config->basedir, "testfile");
			return usage(EXIT_FAILURE);
		} else {
			posix_fadvise(split_config->fd, 0, 0, POSIX_FADV_DONTNEED);
			close(split_config->fd);
			break;
		}
	}

	while (42) {
		memset(split_config->buf, chars[char_num], BUF_SIZE);

		wait_other_thread();

		memset(split_config->buf, chars[char_num], LOCK_LEN);
		pwrite(split_config->control_fd, split_config->buf, BUF_SIZE, 0);
		output("%c", chars[char_num]);

		write_file_byte(split_config->dfd, split_config->basedir, "testfile", split_config->buf, chars[char_num], true);

		char_num = (char_num + 1) % (sizeof(chars)/sizeof(chars[0]));

		nanosleep(&sleep_time, NULL);
	}
	return EXIT_SUCCESS;
}

int run_mode_split(void) {
	char this_char;
	char actual_char1, actual_char2;
	struct timespec sleep_time;
	int char_num = 0;

	if (config->run_mode == READ_MODE) {
		split_config->our_name = "reader";
		split_config->their_name = "writer";
		sleep_time.tv_sec = 0; sleep_time.tv_nsec = 50*MSEC_NS;

		split_config->file_open_flags = O_RDONLY;

	} else {
		split_config->our_name = "writer";
		split_config->their_name = "reader";
		sleep_time.tv_sec = 0; sleep_time.tv_nsec = 500*MSEC_NS;

		split_config->file_open_flags = O_RDWR | O_CREAT;
	}

	split_config->our_run_lock.l_len = split_config->their_run_lock.l_len = LOCK_LEN;
	split_config->our_run_lock.l_whence = split_config->their_run_lock.l_whence = SEEK_SET;
	split_config->our_run_lock.l_type = F_WRLCK;
	split_config->their_run_lock.l_type = F_RDLCK;

	if ((split_config->dfd = open(split_config->basedir, O_RDONLY|O_DIRECTORY)) < 0) {
		output("unable to open directory '%s': %m\n", split_config->basedir);
		return usage(EXIT_FAILURE);
	}

	posix_memalign((void **)&split_config->buf, 4096, BUF_SIZE);
	memset(split_config->buf, '\0', BUF_SIZE);
	if (config->run_mode == READ_MODE) {
reopen_control:
		if ((split_config->control_fd = openat(split_config->dfd, "control", O_RDWR|O_DIRECT)) < 0) {
			if (errno == ENOENT) {
				output("waiting for '%s' to create control file\n", split_config->their_name);
				sleep(1);
				goto reopen_control;
			}
			output("unable to open control file '%s/%s': %m\n", split_config->basedir, "control");
			return usage(EXIT_FAILURE);
		}
	} else {
		if ((split_config->control_fd = openat(split_config->dfd, "control", O_RDWR|O_CREAT|O_TRUNC|O_DIRECT, 0644)) < 0) {
			output("unable to open control file '%s/%s': %m\n", split_config->basedir, "control");
			return usage(EXIT_FAILURE);
		}
		/* do these outside our run_lock */
		ftruncate(split_config->control_fd, BUF_SIZE);
		pwrite(split_config->control_fd, split_config->buf, BUF_SIZE, 0);

	}
	// lock our run_lock to indicate we're running
	set_run_lock();


	// flush all cached data for the file
	while (42) {
		if ((split_config->fd = openat(split_config->dfd, "testfile", split_config->file_open_flags, 0644)) < 0) {
			if (config->run_mode == WRITE_MODE) {
				output("could not create/open '%s/%s': %m\n", split_config->basedir, "testfile");
				return usage(EXIT_FAILURE);
			}
			if (errno == ENOENT) {
				sleep(1);
				continue;
			} else {
				output("could not open '%s/%s': %m\n", split_config->basedir, "testfile");
				return usage(EXIT_FAILURE);
			}
		} else {
			posix_fadvise(split_config->fd, 0, 0, POSIX_FADV_DONTNEED);
			close(split_config->fd);
			break;
		}
	}

	while (42) {
//		output("%c\r", spinner[spinner_num]);
//		spinner_num= (spinner_num + 1) % (sizeof(spinner)/sizeof(spinner[0]));

restart_loop:
		if (config->run_mode == WRITE_MODE)
			memset(split_config->buf, chars[char_num], BUF_SIZE);

		wait_other_thread();

		if (config->run_mode == READ_MODE) {
			actual_char1 = read_file_byte(split_config->dfd, split_config->basedir, "testfile", split_config->buf, true);

			if (actual_char1 == '\0')
				goto restart_loop;

			this_char = read_file_byte(split_config->dfd, split_config->basedir, "testfile", split_config->buf, false);
			if (this_char == '\0')
				goto restart_loop;

			actual_char2 = read_file_byte(split_config->dfd, split_config->basedir, "testfile", split_config->buf, true);
			if (this_char != actual_char1 && this_char != actual_char2) {
				if (actual_char1 == actual_char2) {
					output("found stale data: expected '%c', but found '%c'\n",
						actual_char1, this_char);
				} else {
					output("found stale data: expected either '%c' or '%c', but found '%c'\n",
						actual_char1, actual_char2, this_char);
				}
				return EXIT_SUCCESS;
			}
		} else { // WRITE_MODE
			memset(split_config->buf, chars[char_num], LOCK_LEN);
			pwrite(split_config->control_fd, split_config->buf, BUF_SIZE, 0);
			output("%c", chars[char_num]);

			write_file_byte(split_config->dfd, split_config->basedir, "testfile", split_config->buf, chars[char_num], true);

			char_num = (char_num + 1) % (sizeof(chars)/sizeof(chars[0]));
		}

		nanosleep(&sleep_time, NULL);
	}
	return EXIT_SUCCESS;
}
int run_mode_single_read(void) {
	struct timespec sleep_time = { .tv_sec = 0, .tv_nsec = (5 * MSEC_NS) };
	char start_char, end_char, read_char;
	run_state_t current_run_state;
	char *buf;

	posix_memalign((void **)&buf, 4096, BUF_SIZE);
	memset(buf, '\0', BUF_SIZE);


	while (42) {
		mb();
		current_run_state = single_config->run_state; // just read once per loop

		if (current_run_state == run_state_pause) {
			wait_for_state_cond(single_config->run_state != run_state_pause);
		} else if (current_run_state == run_state_run) {
			mb();
			start_char = single_config->current_char;
			read_char = read_file_byte(single_config->nfs_dfd, single_config->nfs_dir, "testfile", buf, false);
			if (read_char == '\0')
				continue;
			mb();
			end_char = single_config->current_char;

			if (read_char != start_char && read_char != end_char) {
				single_config->run_state = run_state_pause;
				mb();

				single_config->stale_expected1 = start_char;
				single_config->stale_expected2 = end_char;
				single_config->stale_read = read_char;
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
	char *buf;
	int char_num = 0;
	int spinner_num = 0;
	run_state_t current_run_state;
        struct timespec sleep_time = { .tv_sec = 0, .tv_nsec = (250 * MSEC_NS) };

        posix_memalign((void **)&buf, 4096, BUF_SIZE);
        memset(buf, '\0', BUF_SIZE);

	write_file_byte(single_config->local_dfd, single_config->local_dir,"testfile", buf, chars[char_num], true);
	single_config->run_state = run_state_run;

	while (42) {
		single_config->current_char = chars[char_num];
		mb();
		current_run_state = single_config->run_state; // just read once per loop

		if (current_run_state == run_state_pause) {
			wait_for_state_cond(current_run_state != run_state_pause);
		} else if (current_run_state == run_state_run) {
			output("\r%c", spinner[spinner_num]);
			spinner_num = (spinner_num + 1) % (sizeof(spinner)/sizeof(spinner[0]));

			write_file_byte(single_config->local_dfd, single_config->local_dir,"testfile", buf, chars[char_num], true);
			char_num = (char_num + 1) % (sizeof(chars)/sizeof(chars[0]));

			nanosleep(&sleep_time, NULL);
		} else if (current_run_state == run_state_check_stale) {
			char direct_char, read_char;

			output("possible stale found: ");
			if (single_config->stale_expected1 == single_config->stale_expected2)
				output("expected '%c', but found '%c'",
					single_config->stale_expected1, single_config->stale_read);
			else
				output("expected '%c' or '%c', but found '%c'",
					single_config->stale_expected1, single_config->stale_expected2, single_config->stale_read);

			direct_char = read_file_byte(single_config->nfs_dfd, single_config->nfs_dir, "testfile", buf, true);
			read_char = read_file_byte(single_config->nfs_dfd, single_config->nfs_dir, "testfile", buf, false);

			if (direct_char != read_char) {
				output(" -- confirmed stale data: file has '%c', but returns cached '%c'\n",
					direct_char, read_char);
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
	int fd;

	if ((single_config->local_dfd = open(single_config->local_dir, O_RDONLY|O_DIRECTORY)) < 0) {
		output("error opening local directory '%s': %m\n", single_config->local_dir);
		return usage(EXIT_FAILURE);
	}
	if ((single_config->nfs_dfd = open(single_config->nfs_dir, O_RDONLY|O_DIRECTORY)) < 0) {
		output("error opening nfs directory '%s': %m\n", single_config->nfs_dir);
		return usage(EXIT_FAILURE);
	}


	unlinkat(single_config->local_dfd, "testfile", 0);
	if ((fd = openat(single_config->local_dfd, "testfile", O_RDWR|O_CREAT|O_TRUNC|O_DIRECT, 0644)) < 0) {
		output("unable to open test file '%s/%s': %m\n", single_config->local_dir, "testfile");
		return usage(EXIT_FAILURE);
	}
	ftruncate(fd, BUF_SIZE);
	posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
	close(fd);

	if ((fd = openat(single_config->nfs_dfd, "testfile", O_RDONLY)) < 0) {
		output("unable to open test file '%s/%s': %m\n", single_config->nfs_dir, "testfile");
		return usage(EXIT_FAILURE);
	}
	posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
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


//	config = mmap(NULL, sizeof(struct config_struct), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
//	config = malloc(sizeof(struct config_struct));
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
		single_config->nfs_dir = strdup(argv[2]);
		return run_mode_single();
	} else
		return usage(EXIT_FAILURE);

	return EXIT_FAILURE;
}
