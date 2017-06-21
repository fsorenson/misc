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

//#include <linux/elf.h>
//#include <link.h>

#include "libchipper.h"

#define INPUT_BUFFER_SIZE (32ULL * 1024ULL)

struct mulch {
	int fd;
	struct chipper *chip;
	char *buf;
	ssize_t buf_len;
	int interrupted;

	bool config_background;
	bool config_passthru;
	bool config_timestamp;
	char *config_output_file;
	enum tstamp_precision config_tstamp_precision;
	ssize_t config_rotate_size;
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
		if (len <= 0)
			break;

		mulch.buf[len] = '\0';

		if (mulch.config_passthru) /* do we need/want timestamping on the passthrough as well? */
			dprintf(STDOUT_FILENO, "%s", mulch.buf);

		if (mulch.config_timestamp) {
			mulch.chip->chipprintf("%s", mulch.buf);
		} else {
			/* just use the bulk write() function */
			mulch.chip->chipwrite(mulch.buf, len);
		}
	}
}

int input_wait(void) {
	struct pollfd fds[1];
	int poll_num;
	nfds_t nfds = 1;

	fds[0].fd = mulch.fd;
	fds[0].events = POLLIN;

	while (mulch.interrupted == 0) {
		poll_num = poll(fds, nfds, -1);
		if (poll_num == -1) {
			if (errno == EINTR)
				continue;
			dprintf(STDERR_FILENO, "poll error: %m\n");
			exit(EXIT_FAILURE);
		}

		if (poll_num > 0) { /* bytes are available */
			if (fds[0].revents & POLLIN)
				handle_data();
			if (fds[0].revents & POLLHUP)
				mulch.interrupted++;
			short remain = fds[0].revents & ~(POLLIN|POLLHUP);
			if (remain)
				printf("unhandled revents: %x\n", remain);
		}
	}
	return 0;
}

void set_line_buf(int fd) {
	FILE *f;

	f = fdopen(fd, "r");
	setlinebuf(f);
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
	printf("usage: %s [-b|-p] [-t <none|s|ms|us|ns>] [-s <size>] <output_log>\n", exec_name);
	printf("\t-b - execute in background (can't be used with -p)\n");
	printf("\t-p - pass output through, in addition to logging (can't be used with -b)\n");
	printf("\t-t <none|s|ms|us|ns> - disable or enable timestamps with precision:\n");
	printf("\t\tnone - no timestamps\n");
	printf("\t\ts - timestamp with precision of 1 second \n");
	printf("\t\tms - timestamp with precision of 1 ms\n");
	printf("\t\tus - timestamp with precision of 1 us\n");
	printf("\t\tns - timestamp with precision of 1 ns\n");
	printf("\t-s <size> - set the size at which to rotate and compress the plaintext log\n");
	printf("\t\taccepts suffixes such as K, M, G\n");
	printf("\t<output_log> - the compressed output file containing the logged data\n");
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
	}
	val *= mult;
	ret = lrint(val);
	return lrint(ret);
}

int parse_args(int argc, char *argv[]) {
	bool background = false;
	bool passthru = false;
//	bool quiet = false;
//	char *tmpdir = NULL;
	enum tstamp_precision timestamp = tstamp_precision_ns;
//	ssize_t rotate_size = -1;

	static struct option long_options[] = {
		{ "background",	no_argument,		NULL, 'b' },
		{ "passthrough",	no_argument,		NULL, 'p' },
		{ "tstamp",	required_argument,	NULL, 't' },
		{ "size",	required_argument,	NULL, 's' },
		{ 0, 0, 0, 0 }
	};
	char *ptr;
	int opt;
	int err = 0;

	while (1) {
		opt = getopt_long(argc, argv, "bpt:s:", long_options, &optind);
		if (opt == -1)
			break;
		switch (opt) {
			case 'b':
				if (passthru)
					printf("Can't set both passthrough and background\n");
				else
					background = true;
				break;
			case 'p':
				if (background)
					printf("Can't set both passthrough and background\n");
				else
					passthru = true;
				break;
			case 't':
				ptr = optarg ? optarg : argv[optind];
				if (!strcmp("none", ptr))
					timestamp = tstamp_none;
				else if (!strcmp("s", ptr))
					timestamp = tstamp_precision_s;
				else if (!strcmp("ms", ptr))
					timestamp = tstamp_precision_ms;
				else if (!strcmp("us", ptr))
					timestamp = tstamp_precision_us;
				else if (!strcmp("ns", ptr))
					timestamp = tstamp_precision_ns;
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

	if (timestamp == tstamp_none)
		mulch.config_timestamp = false;
	else {
		mulch.config_timestamp = true;
		mulch.config_tstamp_precision = timestamp;
	}
	mulch.config_passthru = passthru;
	mulch.config_background = background;

	if (mulch.config_rotate_size < (typeof(mulch.config_rotate_size))MIN_LOG_ROTATE_SIZE)
		mulch.config_rotate_size = MIN_LOG_ROTATE_SIZE;

/*
	printf("parse_args:\n");
	printf("\tpassthrough: %d\n", passthru);
	printf("\tbackground: %d\n", background);
	printf("timestamp: %d\n", timestamp);
	printf("rotate size: %lu\n", mulch.config_rotate_size);
	printf("output file: %s\n", mulch.config_output_file);
*/

	return err;
}

int main(int argc, char *argv[]) {
	(void)argc;
	(void)argv;
	int ret;

	if ((ret = parse_args(argc, argv)))
		return EXIT_FAILURE;

	if ((mulch.chip = new_chipper(mulch.config_output_file)) == NULL) {
		dprintf(STDERR_FILENO, "Could not create chipper\n");
		return EXIT_FAILURE;
	}
	mulch.chip->set_rotate_size(mulch.config_rotate_size);
	if (mulch.config_timestamp) {
		mulch.chip->set_tstamp_precision(mulch.config_tstamp_precision);
		mulch.chip->set_tstamp_onoff(1);
	} else {
		mulch.chip->set_tstamp_onoff(0);
	}
	mulch.fd = STDIN_FILENO;
	mulch.buf = malloc(INPUT_BUFFER_SIZE + 1);
	mulch.buf_len = INPUT_BUFFER_SIZE + 1;

//	mulch.chip->chipprintf("this is a test\n");

	set_sigs();
	set_line_buf(mulch.fd);

	if (!mulch.config_background || (mulch.config_background && (fork() == 0))) {
		input_wait();

		mulch.chip->exit();
	}

	return EXIT_SUCCESS;
}

