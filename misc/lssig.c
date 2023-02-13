/*
	This file is part of 'lssig'

	Copyright 2013 Frank Sorenson (frank@tuxrocks.com)


    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>

struct sig_field_struct {
	char *str;
	char *desc;
	char *long_opt;
	char short_opt;
};

struct sig_field_struct sig_field[] = {
	{ "SigPnd", "Pending", "pending", 'e' },
	{ "ShdPnd", "Shared Pending", "shared", 's' },
	{ "SigBlk", "Blocked", "blocked", 'b' },
	{ "SigIgn", "Ignored", "ignored", 'i' },
	{ "SigCgt", "Caught", "caught", 'c' },
	{ NULL, NULL, NULL, 0}
};

int sig_field_count = (sizeof(sig_field) / sizeof(struct sig_field_struct)) - 1;

struct options_struct {
	pid_t *pids;
	int pid_count;
	int *display_sig_fields;
	int display_all_fields;
} options;

void read_pid_file(int fd);
int add_pid(pid_t pid) {
	void *ret;

	ret = realloc(options.pids,
		(options.pid_count + 1) * sizeof(pid_t));
	if (ret == NULL) {
		printf("Unable to allocate memory to add pid %d: %s\n",
			pid, strerror(errno));
		exit(-1);
	}
	options.pids = ret;

	options.pids[options.pid_count] = pid;
	options.pid_count ++;

	return options.pid_count;
}

void add_pid_string(const char *optarg) {
	long arg_l;

	arg_l = strtol(optarg, NULL, 10);
	if (arg_l < 1) {
		printf("Invalid PID specified: '%s'\n", optarg);
	} else
		add_pid(arg_l);
}

void decode_sig_val(uint64_t sig_mask) {
	uint64_t i;

	for (i = 0 ; i < 64 ; i ++) {
		if (sig_mask & (1ull << i)) {
			printf("\t\t%lu: %s\n", i, strsignal(i));
		}
	}
}
void parse_sig_str(const char *str) {
	uint64_t sig_mask = 0;

	if (sscanf(str, "%16lx", &sig_mask) == 1)
		decode_sig_val(sig_mask);
}

void parse_opts(int argc, char *argv[]) {
	char short_options[32] = {0};
	struct option *long_options;
	int l_opt = 0, s_opt = 0;

	int opt = 0, long_index = 0;
	int i;

	options.pid_count = 0;
	options.display_sig_fields = calloc(sig_field_count, sizeof(int));

	long_options = calloc(sig_field_count + 3, sizeof(struct option));

	for (i = 0 ; i < sig_field_count ; i ++) {
		long_options[l_opt++] = (struct option){
			sig_field[i].long_opt,
			no_argument,
			&options.display_sig_fields[i],
			sig_field[i].short_opt };
		short_options[s_opt++] = sig_field[i].short_opt;
	}
	long_options[l_opt++] = (struct option){ "all", no_argument, &options.display_all_fields, 'a' };
	short_options[s_opt++] = 'a';

	long_options[l_opt++] = (struct option){ "pid", required_argument, 0, 'p' };
	short_options[s_opt++] = 'p'; short_options[s_opt++] = ':';

	short_options[s_opt++] = 'f'; short_options[s_opt++] = ':';

	long_options[l_opt++] = (struct option){ "decode", required_argument, 0, 'D' };
	short_options[s_opt++] = 'D'; short_options[s_opt++] = ':';

	opterr = 0;
	while ((opt = getopt_long(argc, argv, short_options, long_options, &long_index)) != -1) {
		switch (opt) {
			case 'a':
				options.display_all_fields = 1;
				break;
			case 'f': {
				int fd;
				for (i = 0 ; i < sig_field_count ; i ++)
					options.display_sig_fields[i] = 1;
				options.display_all_fields = 1;
				printf("opening %s\n", optarg);
				if ((fd = open(optarg, O_RDONLY)) >= 0) {
					read_pid_file(fd);
					close(fd);
				}
				printf("done processing file \n");
				exit(0);
				  }
				break;
			case 'p':
				add_pid_string(optarg);
				break;
			case 'D':
				parse_sig_str(optarg);
				exit(1);
				break;
			case '?':
				printf("Unknown option: %c\n", opt);
				break;
			default:
				for (i = 0 ; i < sig_field_count ; i ++) {
					if (sig_field[i].short_opt == opt) {
						options.display_sig_fields[i] = 1;
						i = sig_field_count;
					}
				}
				break;
		}
	}
	while (optind < argc) {
		add_pid_string(argv[optind++]);
	}

	if (options.display_all_fields) {
		for (i = 0 ; i < sig_field_count ; i ++)
			options.display_sig_fields[i] = 1;
	} else {
		int count = 0;
		for (i = 0 ; i < sig_field_count ; i ++)
			count += options.display_sig_fields[i];
		if (! count)
			for (i = 0 ; i < sig_field_count ; i ++)
				options.display_sig_fields[i] = 1;
	}
	if (! options.pid_count)
		add_pid(getppid()); // add the pid of the calling process
}

int is_sig_hdr(const char *hdr) {
	int i = 0;

	while (sig_field[i].str != NULL) {
		if (! strcmp(hdr, sig_field[i].str))
			return i;
		i++;
	}

	return -1;
}

void parse_sig_line(const char *line) {
	char *sig_header;
	int ret;
	uint64_t sig_mask = 0;
//	uint64_t i;

//printf("parse_sig_line for '%s'\n", line);

	if ((ret = sscanf(line, "%m[a-zA-Z]: %16lX", &sig_header, &sig_mask)) != 2) {
		if (ret == 1)
			goto out;
		return;
	}

	if ((ret = is_sig_hdr(sig_header)) < 0)
		goto out;
printf("it's a sig header, I guess\n");
	if (! options.display_sig_fields[ret])
		goto out;
printf("here\n");
	printf("\t%s (%s):\n", sig_header, sig_field[ret].desc);

	decode_sig_val(sig_mask);
/*
	for (i = 0 ; i < 64 ; i ++) {
		if (sig_mask & (1ull << i)) {
			printf("\t\t%lu: %s\n", i, strsignal(i));
		}
	}
*/
out:
	free(sig_header);
}

void read_pid_file(int fd) {
#define BUFFER_SIZE 4096
	char buffer[BUFFER_SIZE];
	int buffer_size = BUFFER_SIZE;
#undef BUFFER_SIZE
	int fsize;
	char *p, *end_p;
	int ret = -1;

	if ((ret = read(fd, buffer, buffer_size)) == -1) {
		printf("Error occurred while reading status file: %s\n", strerror(errno));
		return;
	}
	fsize = ret;
	lseek(fd, 0, SEEK_SET);

	p = buffer;
	while ((end_p = memchr(p, '\n', fsize)) != NULL) {
		*end_p = '\0';
		end_p ++;
		parse_sig_line(p);

		p = end_p;
		if (*p == '\0')
			break;
	}
}

void parse_pid_file(const int pid) {
#define PID_STATUS_FILE_LEN 200
	static char pid_status_file[PID_STATUS_FILE_LEN] = { 0 };
	size_t pid_status_file_len = PID_STATUS_FILE_LEN;
#undef PID_STATUS_FILE_LEN
	int ret;
	int fd;

	if ((ret = snprintf(pid_status_file, pid_status_file_len, "/proc/%d/status", pid)) < 0) {
		printf("Error occurred while constructing filename for /proc/%d/status: %s\n",
			pid, strerror(errno));
		return;
	}
	if ((fd = open(pid_status_file, O_RDONLY)) == -1) {
		printf("Error occurred while opening %s: %s\n", pid_status_file, strerror(errno));
		return;
	}
	read_pid_file(fd);
	close(fd);
}

void parse_pid_files(void) {
	int i;

	for (i = 0 ; i < options.pid_count ; i ++) {
		printf("pid %d\n", options.pids[i]);
		parse_pid_file(options.pids[i]);
	}
}

int main(int argc, char *argv[]) {

	parse_opts(argc, argv);

	parse_pid_files();

	return 0;
}
