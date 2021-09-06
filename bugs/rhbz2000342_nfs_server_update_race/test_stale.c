#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>


#define COMPILE_TIME_ASSERT(cond) \
	extern void compile_time_assert(int arg[(cond) ? 1 : -1])

#define USEC_NS (1000)
#define MSEC_NS (USEC_NS * 1000)
#define BUF_SIZE 4096
#define BASEDIR "/mnt/tmp"

#define CHECK_RUNNING_COUNTER 1000

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


//const char *subdirs[] = { "adex", "adfn", "adhr", "adis", "adit", "admk", "adop", "adpb", "adpr", "adsl", "bcom", "bhro", "bsto", "efin", "ehro", "emkt", "eopr", "epbu", "eprd", "esls", "mcfn", "mcom", "mfin", "mlpo", "mmer", "mspc", "msto", "uadt", "ucfn", "ucom", "uhro", "uito", "ulpo", "umer", "umtn", "upub", "uspc", "ustd", "usto", };
const char *subdirs[] = { };
#define NUM_SUBDIRS (sizeof(subdirs)/sizeof(subdirs[0]))


COMPILE_TIME_ASSERT(LOCK_LEN >= NUM_SUBDIRS + 1);

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

typedef enum read_write_mode { READ_MODE, WRITE_MODE } read_write_mode_t;
typedef struct config_struct {
	read_write_mode_t run_mode;
	int control_fd;
	int file_open_flags;
	struct flock control_lock;
//	struct flock run_lock_r;
//	struct flock run_lock_w;
	struct flock our_run_lock;
	struct flock their_run_lock;
	char *our_name;
	char *their_name;
} config_struct_t;
config_struct_t config;

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
bool they_run(void) {
	config.their_run_lock.l_type = F_RDLCK;
	fcntl(config.control_fd, F_GETLK, &config.their_run_lock);

	if (config.their_run_lock.l_type != F_UNLCK) {
//		printf("they have their run_lock...  start: %ld, length: %ld, lock_type: %s\n",
//			config.their_run_lock.l_start, config.their_run_lock.l_len,
//			lock_type_to_str(config.their_run_lock.l_type));
	}


	return (config.their_run_lock.l_type == F_UNLCK) ? false : true;
}

void set_run_lock(void) {
	config.our_run_lock.l_type = F_WRLCK;
	if (config.run_mode == READ_MODE) {
		config.our_run_lock.l_start = CONTROL_READER_OFFSET;
		config.their_run_lock.l_start = CONTROL_WRITER_OFFSET;
	} else {
		config.our_run_lock.l_start = CONTROL_WRITER_OFFSET;
		config.their_run_lock.l_start = CONTROL_READER_OFFSET;

	}
	fcntl(config.control_fd, F_SETLKW, &config.our_run_lock);
}

void wait_other_thread(void) {
	static bool reported_online = false;
	bool reported_offline = false;
	unsigned int count = 0;

	while (!they_run()) {
		if (!reported_offline) {
			output("waiting for '%s' to come online\n", config.their_name);
			reported_offline = true;
			reported_online = false;
		}
		usleep(10000);
	}
	if (!reported_online) {
		output("'%s' is online\n", config.their_name);
		reported_online = true;
		reported_offline = false;
	}

}
void unlock_control_0(void) {
	config.control_lock.l_type = F_UNLCK;
	fcntl(config.control_fd, F_SETLK, &config.control_lock);
}
void unlock_control(void) {
}

void lock_control_0(void) {
//	short control_lock_mode = (config.run_mode == READ_MODE) ? F_WRLCK : F_RDLCK;
	short control_lock_mode = F_WRLCK;
relock_control:
	config.control_lock.l_type = control_lock_mode;
	fcntl(config.control_fd, F_SETLKW, &config.control_lock);

	if (!they_run()) {
		unlock_control();
		output("waiting for '%s' to come online\n", config.their_name);
		sleep(1);
		goto relock_control;
	}
}
void lock_control(void) {
	while (!they_run()) {
		output("waiting for '%s' to come online\n", config.their_name);
		sleep(1);
	}
}

int usage(const char *exe, int ret) {
	output("usage: %s <read | write>\n", exe);
	return ret;
}

int main(int argc, char *argv[]) {
	char **filenames, *out, *old_out, *buf, *control_buf, *control_buf2;
	int *iters_without_change, max_without_change = 0, max_ever = 0;
	struct timespec sleep_time;
	int dfd, *fds;
	int char_num = 0, i, spinner_num = 0;
	unsigned long check_running_counter = CHECK_RUNNING_COUNTER;
	int change_count;
	bool found_stale;

	if (argc != 2)
		return usage(argv[0], EXIT_FAILURE);

	config.control_lock.l_start = 0;
	config.control_lock.l_len = config.our_run_lock.l_len = config.their_run_lock.l_len = LOCK_LEN;
	config.control_lock.l_whence = config.our_run_lock.l_whence = config.their_run_lock.l_whence = SEEK_SET;
	config.our_run_lock.l_type = F_WRLCK;
	config.their_run_lock.l_type = F_RDLCK;

	if (!strcmp(argv[1], "read")) {
		config.run_mode = READ_MODE;
		config.our_name = "reader";
		config.their_name = "writer";
		sleep_time.tv_sec = 0; sleep_time.tv_nsec = 5*MSEC_NS;
		config.control_lock.l_type = F_WRLCK;

		config.file_open_flags = O_RDONLY;
	} else if (!strcmp(argv[1], "write")) {
		config.run_mode = WRITE_MODE;
		config.our_name = "writer";
		config.their_name = "reader";
		sleep_time.tv_sec = 0; sleep_time.tv_nsec = 250*MSEC_NS;
		config.control_lock.l_type = F_RDLCK;

		config.file_open_flags = O_RDWR | O_CREAT;
	} else
		return usage(argv[0], EXIT_FAILURE);

	if ((dfd = open(BASEDIR, O_RDONLY|O_DIRECTORY)) < 0) {
		output("unable to open directory '%s': %m\n", BASEDIR);
		return usage(argv[0], EXIT_FAILURE);
	}

	posix_memalign((void **)&control_buf, 4096, BUF_SIZE);
	posix_memalign((void **)&control_buf2, 4096, BUF_SIZE);
	memset(control_buf, '\0', BUF_SIZE);
	if (config.run_mode == READ_MODE) {
reopen_control:
		if ((config.control_fd = openat(dfd, "control", O_RDWR|O_DIRECT)) < 0) {
			if (errno == ENOENT) {
				output("waiting for '%s' to create control file\n", config.their_name);
				goto reopen_control;
			}
			output("unable to open control file '%s/%s': %m\n", BASEDIR, "control");
			return usage(argv[0], EXIT_FAILURE);
		}
	} else {
		if ((config.control_fd = openat(dfd, "control", O_RDWR|O_CREAT|O_TRUNC|O_DIRECT, 0644)) < 0) {
			output("unable to open control file '%s/%s': %m\n", BASEDIR, "control");
			return usage(argv[0], EXIT_FAILURE);
		}
		/* do these outside our run_lock */
		ftruncate(config.control_fd, BUF_SIZE);
//		pwrite(config.control_fd, control_buf, LOCK_LEN, 0);
		pwrite(config.control_fd, control_buf, BUF_SIZE, 0);
	}

	// lock our run_lock to indicate we're running
	set_run_lock();

	posix_memalign((void **)&buf, 4096, BUF_SIZE);

	filenames = malloc((NUM_SUBDIRS + 1) * sizeof(char *));
	fds = malloc((NUM_SUBDIRS + 1) * sizeof(int));

	if (config.run_mode == READ_MODE) {
		out = malloc(NUM_SUBDIRS + 2);
		memset(out, '\0', NUM_SUBDIRS + 2);

		old_out = malloc(NUM_SUBDIRS + 2);
		memset(old_out, '\0', NUM_SUBDIRS + 2);
		iters_without_change = malloc((NUM_SUBDIRS+1)*sizeof(int));
		memset(iters_without_change, 0, (NUM_SUBDIRS+1)*sizeof(int));

		memset(control_buf, '\0', BUF_SIZE);
	}


	for (i = 0 ; i < NUM_SUBDIRS ; i++)
		asprintf(&filenames[i], "%s/test_file_in_%s", subdirs[i], subdirs[i]);
	filenames[NUM_SUBDIRS] = strdup("test_file_in_basedir");


	// flush all cached data for the files
	for (i = 0 ; i <= NUM_SUBDIRS ; i++) {
retry_flush:
		if ((fds[i] = openat(dfd, filenames[i], config.file_open_flags)) < 0) {
			if (config.run_mode == WRITE_MODE) {
				output("could not create/open '%s': %m\n", filenames[i]);
				return usage(argv[0], EXIT_FAILURE);
			}
			if (errno == ENOENT) {
				sleep(1);
				goto retry_flush;
			} else {
				output("could not open '%s': %m\n", filenames[i]);
				return usage(argv[0], EXIT_FAILURE);
			}
		}
		posix_fadvise(fds[i], 0, 0, POSIX_FADV_DONTNEED);
		close(fds[i]);
	}


	while (42) {
		output("%c\r", spinner[spinner_num]);
		spinner_num= (spinner_num + 1) % (sizeof(spinner)/sizeof(spinner[0]));

restart_loop:
		if (config.run_mode == READ_MODE) {
			memcpy(old_out, out, NUM_SUBDIRS + 2);
//			have_change = false;
			change_count = 0;
			max_without_change = 0;
		} else
			memset(buf, chars[char_num], BUF_SIZE);

//		lock_control();
//		if (--check_running_counter == 0) {
			wait_other_thread();
//			check_running_counter = CHECK_RUNNING_COUNTER;
//		}

		if (config.run_mode == READ_MODE) {
//output("have lock... reading from control\n");
//			pread(config.control_fd, control_buf, LOCK_LEN, 0);
			pread(config.control_fd, control_buf, BUF_SIZE, 0);
			if (control_buf[0] == '\0') {
				unlock_control();
				goto restart_loop;
			}
//output("have lock...  reading\n");
//output("control_buf: %s\n", control_buf);
		} else {
			memset(control_buf, chars[char_num], LOCK_LEN);
//			control_buf[0] = buf[0];
//			pwrite(config.control_fd, control_buf, LOCK_LEN, 0);
			pwrite(config.control_fd, control_buf, BUF_SIZE, 0);
			output("%c", chars[char_num]);
		}

		for (i = 0 ; i <= NUM_SUBDIRS ; i++) {
			if (config.run_mode == READ_MODE) {
				if ((fds[i] = openat(dfd, filenames[i], O_RDONLY)) < 0) {
					output("error opening '%s': %m\n", filenames[i]);
					exit(-1);
				}
//retry_read:
				pread(fds[i], buf, BUF_SIZE, 0);
				if (buf[0] == '\0') {
					close(fds[i]);
					unlock_control();
					goto restart_loop;
//					goto retry_read;
				}
				out[i] = buf[0];
				if (out[i] != old_out[i]) {
					iters_without_change[i] = 0;
					change_count++;
				} else
					iters_without_change[i]++;
				max_without_change = max(max_without_change, iters_without_change[i]);

//output("control: '%c', out[%d]: '%c'\n", control_buf[0], i, out[i]);
/*
if (out[i] != control_buf[0]) {
	output("found stale data in '%s/%s' - control: '%c', file contents: '%c'\n", BASEDIR, filenames[i], control_buf[0], buf[0]);
	found_stale = true;
}
*/
//					have_change = true;

			} else {
				if ((fds[i] = openat(dfd, filenames[i], O_RDWR|O_CREAT, 0644)) < 0) {
					output("error opening '%s': %m\n", filenames[i]);
					exit(-1);
				}
				pwrite(fds[i], buf, BUF_SIZE, 0);
			}
			close(fds[i]);
		}
		if (config.run_mode == READ_MODE) {
			pread(config.control_fd, control_buf2, BUF_SIZE, 0);
			for (i = 0 ; i <= NUM_SUBDIRS ; i++) {
//				if (out[i] != control_buf[i]) {
//					pread(config.control_fd, control_buf2, BUF_SIZE, 0);
//					if (control_buf[i] != control_buf2[i]) {


//				if (out[i] != control_buf[i]) {
				if (out[i] != control_buf[i] && out[i] != control_buf2[i]) {
					if (control_buf[i] == control_buf2[i]) {
						output("found a file with stale data: %s/%s - expected '%c', but found '%c'\n",
							BASEDIR, filenames[i], control_buf[i], out[i]);
					} else {
						output("found a file with stale data: %s/%s - expected either '%c' or '%c', but found '%c'\n",
							BASEDIR, filenames[i], control_buf[i], control_buf2[i], out[i]);
					}
					found_stale = true;
				}
			}


			max_ever = max(max_ever, max_without_change);
/*
			output("%d iterations without change (max %d): control: '%c' - %s (%d)\n",
				max_without_change, max_ever, control_buf[0], out, change_count);
*/
//			if (change_count != NUM_SUBDIRS + 1) {
//				output("
//				return EXIT_SUCCES;
//			}
		} else
			char_num = (char_num + 1) % (sizeof(chars)/sizeof(chars[0]));

if (found_stale)
	return EXIT_SUCCESS;


		unlock_control();


		nanosleep(&sleep_time, NULL);
	}
	return EXIT_FAILURE;
}
