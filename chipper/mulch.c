#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <stdbool.h>
#include <errno.h>
#include <math.h>
#include <getopt.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <link.h>

#include "libchipper.h"
#include "DisplayTerminalSettings.h"

#define INPUT_BUFFER_SIZE (32ULL * 1024ULL)

#define DEBUG 0

struct mulch {
	int fd;
	struct chipper *chip;
	char *buf;
	char *follow_filename;
	ssize_t buf_len;
	int interrupted;

	bool config_background;
	bool config_passthru;
	bool config_timestamp;
	char *config_output_file;
	bool output_append;
	enum chipper_tstamp_precision config_tstamp_precision;
	ssize_t config_rotate_size;

	bool config_split_LF;
	bool need_tstamp;
	bool quiet;
} mulch;

void handle_interrupt(int sig) {
	(void)sig;
	mulch.interrupted++;
}

void handle_data(void) {
	ssize_t len;

	while (mulch.interrupted == 0) {
		len = read(mulch.fd, mulch.buf, mulch.buf_len - 1);
		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR || errno == ERESTART)
				continue;
			dprintf(STDERR_FILENO, "error reading log input: %m\n");
			exit(EXIT_FAILURE);
		}
		if (len == 0)
			return;
		if (len < 0)
			break;

		mulch.buf[len] = '\0';


		if (mulch.config_timestamp) {
#if 1
			/* try to split up the buffer by LF - WiP */
			char *p;
			ssize_t remaining = len;

			while (remaining > 0) {
/*
				dprintf(STDOUT_FILENO, "remaining: %ld *", remaining);
				write(STDOUT_FILENO, mulch.buf, remaining);
				dprintf(STDOUT_FILENO, "*\n");
*/
				if (mulch.need_tstamp) {
					mulch.chip->chipprintf("%s", "");
					if (mulch.config_passthru)
						chipper_output_tstamp(STDOUT_FILENO, mulch.config_tstamp_precision);
					mulch.need_tstamp = false;

				}
				if ((p = memchr(mulch.buf, '\n', remaining))) {
					ssize_t bytes;

					p++;
					bytes = p - mulch.buf;
					mulch.chip->chipwrite(mulch.buf, bytes - 1);
					if (mulch.config_passthru)
						write(STDOUT_FILENO, mulch.buf, bytes);
					memmove(mulch.buf, mulch.buf + bytes, remaining - bytes);
					remaining -= bytes;
					mulch.need_tstamp = true;
				} else {
					mulch.chip->chipwrite(mulch.buf, remaining);
					if (mulch.config_passthru)
						write(STDOUT_FILENO, mulch.buf, remaining);
					remaining = 0;
				}
			}
			return;
#else
			mulch.chip->chipprintf("%s", mulch.buf);
			if (mulch.config_passthru) { /* do we need/want timestamping on the passthrough as well? */
//				dprintf(STDOUT_FILENO, "%s", mulch.buf);
				chipper_output_tstamp(STDOUT_FILENO, mulch.config_tstamp_precision);
				write(STDOUT_FILENO, mulch.buf, len);
			}
#endif
		} else {
			/* just use the bulk write() function */
			mulch.chip->chipwrite(mulch.buf, len);
			if (mulch.config_passthru)
//				dprintf(STDOUT_FILENO, "%s", mulch.buf);
				write(STDOUT_FILENO, mulch.buf, len);
		}
	}
}

int input_wait(void) {
	struct timespec timeout = { .tv_sec = 0, .tv_nsec = 250000000 };
	struct pollfd fds[1];
	nfds_t nfds = 1;
	int poll_num;

        sigset_t sigmask;

        sigemptyset(&sigmask);
        sigaddset(&sigmask, SIGINT);
        sigaddset(&sigmask, SIGTERM);

	fds[0].fd = mulch.fd;
	fds[0].events = POLLIN | POLLRDHUP;

	while (mulch.interrupted == 0) {
		poll_num = ppoll(fds, nfds, &timeout, &sigmask);
		if (poll_num == 0)
			continue; /* likely just timed out */
		if (poll_num == -1) {
			if (errno == EINTR) {
				dprintf(STDERR_FILENO, "intr\n");
				exit(0);
				continue;
			}
			dprintf(STDERR_FILENO, "poll error: %m\n");
			exit(EXIT_FAILURE);
		}

		if (poll_num > 0) { /* bytes are available */
			short revents = fds[0].revents;
			if (revents & (POLLHUP | POLLRDHUP)) {
				/* try one final read, in case we haven't consumed everything yet */
				handle_data();
				mulch.interrupted++;
				continue;
			}
			if (revents & POLLIN) {
				revents &= ~POLLIN;
				handle_data();
			}
			if (revents)
				dprintf(STDERR_FILENO, "unhandled revents: %x\n", revents);
		}
	}
	return 0;
}

void set_line_buf(int fd) {
	FILE *f;

	f = fdopen(fd, "r");
	setlinebuf(f);
}

void setup_stdin(int fd) {
	struct termios tios;
	struct termios orig_tios;

	tcgetattr(fd, &orig_tios);

#if DEBUG
	dprintf(STDERR_FILENO, "initial settings for stdin:\n");

	struct stat st;
	fstat(fd, &st);
	dprintf(STDERR_FILENO, "stat->\n"
		"\tst_dev = %x:%x\n"
		"\tst_ino = %lu\n"
		"\tst_rdev = %x:%x\n",
		major(st.st_dev), minor(st.st_dev), st.st_ino, major(st.st_rdev), minor(st.st_rdev));
#endif

#if DEBUG

	DisplayAllTermSettings(&orig_tios);

	dprintf(STDERR_FILENO, "\n\n");


	dprintf(STDERR_FILENO, "decoding of\n"
	"{c_iflags=0x500,\n"
	"c_oflags=0x5,\n"
	"c_cflags=0xbf,\n"
	"c_lflags=0x8a3b,\n"
	"c_line=0,\n"
        "c_cc=\"\\x03\\x1c\\x7f\\x15\\x04\\x00\\x01\\x00\\x11\\x13\\x1a\\x00\\x12\\x0f\\x17\\x16\\x00\\x00\\x00\"}):\n");
	tios.c_iflag = 0x500;
	tios.c_oflag = 0x5;
	tios.c_cflag = 0xbf;
	tios.c_lflag = 0x8a3b;
	tios.c_line = 0;
	DisplayAllTermSettings(&tios);

	printf("\n\n");
#endif

#if DEBUG
	dprintf(STDERR_FILENO, "decoding of\n"
	"{c_iflags=0x2502,\n"
	"c_oflags=0x5,\n"
	"c_cflags=0xbf,\n"
	"c_lflags=0x8a3b,\n"
	"c_line=0,\n"
        "c_cc=\"\\x03\\x1c\\x7f\\x15\\x04\\x00\\x01\\x00\\x11\\x13\\x1a\\x00\\x12\\x0f\\x17\\x16\\x00\\x00\\x00\"}):\n");
	tios.c_iflag = 0x2502;
	tios.c_oflag = 0x5;
	tios.c_cflag = 0xbf;
	tios.c_lflag = 0x8a3b;
	tios.c_line = 0;
	DisplayAllTermSettings(&tios);

	dprintf(STDERR_FILENO, "\n\n");
#endif

#if DEBUG
	dprintf(STDERR_FILENO, "decoding of\n"
        "{c_iflags=0x2502,\n"
        "c_oflags=0x4,\n"
        "c_cflags=0xbf,\n"
        "c_lflags=0x8a3b,\n"
        "c_line=0,\n"
        "c_cc=\"\\x03\\x1c\\x7f\\x15\\x04\\x00\\x01\\x00\\x11\\x13\\x1a\\x00\\x12\\x0f\\x17\\x16\\x00\\x00\\x00\"}):\n");
	tios.c_iflag = 0x2502;
	tios.c_oflag = 0x4;
	tios.c_cflag = 0xbf;
	tios.c_lflag = 0x8a3b;
	tios.c_line = 0;
	DisplayAllTermSettings(&tios);

	dprintf(STDERR_FILENO, "\n\n");
#endif


	tios.c_iflag = 0x500;
	tios.c_oflag = 0x5;
	tios.c_cflag = 0xbf;
	tios.c_lflag = 0x8a3b;
	tios.c_line = 0;
	tcsetattr(fd, TCSANOW, &tios);
}


void set_sigs(void) {
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &handle_interrupt;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

void usage(const char *exec_name) {
	dprintf(STDERR_FILENO, "usage: %s [-a|-o] [-b|-p] [-f <FILE>] [-t <none|s|ms|us|ns>] [-s <size>] <output_log>\n", exec_name);
	dprintf(STDERR_FILENO, "\t-a - append to the output file, rather than overwrite (DEFAULT)\n");
	dprintf(STDERR_FILENO, "\t-o - overwrite the output file, rather than append\n");
	dprintf(STDERR_FILENO, "\n");
	dprintf(STDERR_FILENO, "\t-b - execute in background (can't be used with -p)\n");
	dprintf(STDERR_FILENO, "\t-p - pass output through, in addition to logging (can't be used with -b)\n");
	dprintf(STDERR_FILENO, "\n");
	dprintf(STDERR_FILENO, "\t-f - read from the given file (rather than read from stdin)\n");
	dprintf(STDERR_FILENO, "\n");
	dprintf(STDERR_FILENO, "\t-t <none|s|ms|us|ns|unix|unix_ns> - disable or enable timestamps with precision:\n");
	dprintf(STDERR_FILENO, "\t\tnone - no timestamps\n");
	dprintf(STDERR_FILENO, "\t\ts - timestamp with precision of 1 second \n");
	dprintf(STDERR_FILENO, "\t\tms - timestamp with precision of 1 ms\n");
	dprintf(STDERR_FILENO, "\t\tus - timestamp with precision of 1 us\n");
	dprintf(STDERR_FILENO, "\t\tns - timestamp with precision of 1 ns\n");
	dprintf(STDERR_FILENO, "\t\tunix - unix timestamp with precision of 1 s\n");
	dprintf(STDERR_FILENO, "\t\tunix_ns - unix timestamp with precision of 1 ns\n");
	dprintf(STDERR_FILENO, "\t-s <size> - set the size at which to rotate and compress the plaintext log\n");
	dprintf(STDERR_FILENO, "\t\taccepts suffixes such as K, M, G\n");
	dprintf(STDERR_FILENO, "\t<output_log> - the compressed output file containing the logged data (argument REQUIRED)\n");
}
/*

 /bin/foo | mulch /tmp/foo_output
	-b - background
	-t <none | s | ms | us | ns> - set timestamps and precision
	-p - passthrough as well as log
	-q - quiet
	-t <TMPDIR> - specify a different temp dir (default /tmp)
	-f <INPUT_FILE> - follow this file (instead of reading from stdin)
	-s <SIZE>[kKmMgG] - set rotate size
	-S <SIZE>[kKmMgGtT] - set maximum total size?
	<some sort of stop condition? - total size? #lines? compressed size? duration? until time?
*/

#define get_optional() ({ \
	char *ptr = optarg ? optarg : argv[optind]; \
	if (optarg || argv[optind]) \
		optind++; \
	ptr; \
})


ssize_t parse_size(const char *size_str) {
	double val;
	char *ptr;
	double mult = 1.0;
	ssize_t ret;

	val = strtod(size_str, &ptr);
	if (strlen(ptr) == 1) {
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough="
		switch (*ptr) {
			case 'G':
			case 'g':
				mult *= 1024.0;
			case 'M':
			case 'm':
				mult *= 1024.0;
			case 'K':
			case 'k':
				mult *= 1024.0;
			default:
				break;
		}
#pragma GCC diagnostic warning "-Wimplicit-fallthrough"
	}
	val *= mult;
	ret = lrint(val);
	return lrint(ret);
}

int parse_args(int argc, char *argv[]) {
	enum chipper_tstamp_precision timestamp = chipper_tstamp_precision_ns;
	bool background = false;
	bool passthru = false;

	static struct option long_options[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "quiet",	no_argument,		NULL, 'q' },
		{ "append",	no_argument,		NULL, 'a' },
		{ "overwrite",	no_argument,		NULL, 'o' },
		{ "background",	no_argument,		NULL, 'b' },
		{ "passthrough",	no_argument,		NULL, 'p' },
		{ "follow",	required_argument,	NULL, 'f' },
		{ "tstamp",	required_argument,	NULL, 't' },
		{ "size",	required_argument,	NULL, 's' },
		{ 0, 0, 0, 0 }
	};
	char *ptr;
	int opt;
	int err = 0;

	mulch.follow_filename = NULL;
	mulch.output_append = true; /* default to overwrite */
	mulch.config_split_LF = true; /* future feature, if this becomes necessary */
	while (1) {
		opt = getopt_long(argc, argv, "haoqbpf:t:s:", long_options, &optind);
		if (opt == -1)
			break;
		switch (opt) {
			case 'a':
				mulch.output_append = true;
				break;
			case 'o':
				mulch.output_append = false;
				break;
			case 'q':
				mulch.quiet = true;
				break;
			case 'b':
				if (passthru)
					dprintf(STDERR_FILENO, "Can't set both passthrough and background\n");
				else
					background = true;
				break;
			case 'p':
				if (background)
					dprintf(STDERR_FILENO, "Can't set both passthrough and background\n");
				else
					passthru = true;
				break;
			case 'f':
				ptr = optarg ? optarg : argv[optind];
				mulch.follow_filename = ptr;
				break;
			case 't':
				ptr = optarg ? optarg : argv[optind];
				if (!strcmp("none", ptr))
					timestamp = chipper_tstamp_none;
				else if (!strcmp("s", ptr))
					timestamp = chipper_tstamp_precision_s;
				else if (!strcmp("ms", ptr))
					timestamp = chipper_tstamp_precision_ms;
				else if (!strcmp("us", ptr))
					timestamp = chipper_tstamp_precision_us;
				else if (!strcmp("ns", ptr))
					timestamp = chipper_tstamp_precision_ns;
				else if (!strcmp("ux", ptr) || !strcmp("epoch", ptr))
					timestamp = chipper_tstamp_precision_unix;
				else if (!strcmp("uxns", ptr))
					timestamp = chipper_tstamp_precision_unix_ns;
				break;
			case 's':
				ptr = optarg ? optarg : argv[optind];
				mulch.config_rotate_size = parse_size(ptr);
				if (mulch.config_rotate_size < (typeof(mulch.config_rotate_size)) MIN_LOG_ROTATE_SIZE)
					mulch.config_rotate_size = MIN_LOG_ROTATE_SIZE;
				break;
		}
	}
	/* should be one more arg... the output filename */
	if (optind == argc - 1) {
		mulch.config_output_file = strdup(argv[optind]);
	} else {
		dprintf(STDERR_FILENO, "Error in usage...\n");
		err++;
	}

	if (timestamp == chipper_tstamp_none) {
		mulch.config_timestamp = false;
		mulch.config_tstamp_precision = chipper_tstamp_none;
	} else {
		mulch.config_timestamp = true;
		mulch.config_tstamp_precision = timestamp;
	}
	mulch.config_passthru = passthru;
	mulch.config_background = background;

	if (mulch.config_rotate_size < (typeof(mulch.config_rotate_size))MIN_LOG_ROTATE_SIZE)
		mulch.config_rotate_size = MIN_LOG_ROTATE_SIZE;

	mulch.need_tstamp = mulch.config_timestamp ? true : false;

	return err;
}

int setup_chipper(void) {
	uint32_t chipper_flags = 0;

	if (mulch.follow_filename) {
		if ((mulch.fd = open(mulch.follow_filename, O_RDONLY)) < 0)
			error_exit_fail("Unable to follow filename '%s'\n", mulch.follow_filename);
		lseek(mulch.fd, 0, SEEK_END);
	} else
		mulch.fd = STDIN_FILENO;

	if (mulch.config_timestamp == false)
		chipper_tstamp_set_none(chipper_flags);
	else
		chipper_tstamp_precision_set_bit(chipper_flags, mulch.config_tstamp_precision);
	if (mulch.quiet)
		chipper_set_quiet(chipper_flags);
	if ((mulch.chip = new_chipper(mulch.config_output_file, chipper_flags)) == NULL) {
		dprintf(STDERR_FILENO, "Could not create chipper\n");
		return EXIT_FAILURE;
	}
	mulch.chip->set_rotate_size(mulch.config_rotate_size);

/* may no longer be necessary.... */
/*
	if (mulch.config_timestamp) {
		mulch.chip->set_tstamp_precision(mulch.config_tstamp_precision);
		mulch.chip->set_tstamp_onoff(1);
	} else {
		mulch.chip->set_tstamp_onoff(0);
	}
*/

	mulch.buf = malloc(INPUT_BUFFER_SIZE + 1);
	mulch.buf_len = INPUT_BUFFER_SIZE + 1;

	set_sigs();
	setup_stdin(mulch.fd);
//	exit(0);
//	set_line_buf(mulch.fd);

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
	(void)argc;
	(void)argv;
	int ret;

	if ((ret = parse_args(argc, argv))) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (setup_chipper() != EXIT_SUCCESS)
		return EXIT_FAILURE;

	if (!mulch.config_background || (mulch.config_background && (fork() == 0))) {
		input_wait();

		mulch.chip->exit();
	}

	return EXIT_SUCCESS;
}

