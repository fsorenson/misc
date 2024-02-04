#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <sched.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <utime.h>
#include <getopt.h>
#include <errno.h>
#include <pcre.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>


#define KiB (1024UL)
#define MiB (KiB * KiB)

#define BUF_SIZE (1 * MiB)
#define OVECCOUNT 30

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define min(a,b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a < _b ? _a : _b; \
})

#define free_mem(p) do { \
	if (p) \
		free(p); \
	p = NULL; \
} while (0)

typedef enum {
	regex_extract_pid,
	regex_extract_timestamp,
	regex_extract_delay,
	regex_extract_elapsed,
	regex_split_syscall,
} regex_ids;


#define CAP_GROUP_START_OFFSET(o, num) ( o[2 * num] )
#define CAP_GROUP_END_OFFSET(o, num) ( o[2 * num + 1] )
//#define CAP_GROUP_START(line, o, num) ({ line + o[2 * num]; })
#define CAP_GROUP_START(line, o, num) ( line + CAP_GROUP_START_OFFSET(o, num) )
#define CAP_GROUP_LEN(o, num) ( CAP_GROUP_END_OFFSET(o, num) - CAP_GROUP_START_OFFSET(o, num) )


#define REGEX_STR_DIGITS "[0-9]+"

#define REGEX_STR_STANDARD_PID	"(?:" REGEX_STR_DIGITS ")"
#define REGEX_STR_ALT_PID	"(?:(?:\\[pid )" REGEX_STR_DIGITS "(?:\\]))"
#define REGEX_STR_PID		"(?:(?:" REGEX_STR_STANDARD_PID ")|(::" REGEX_STR_ALT_PID "))"
#define REGEX_STR_EXTRACT_PID	"^(" REGEX_STR_PID ")\\s+(.+)$"

#define REGEX_STR_TIME_HOURS	"(?:(?:[01][0-9])|(?:2[0-3]))"
#define REGEX_STR_TIME_MINUTES	"(?:[0-5][0-9])"
#define REGEX_STR_TIME_SECONDS	"(?:(?:[0-5][0-9])|60)"  /* 23:59:60 is posible for leap second */
#define REGEX_STR_TIME_SUBSECS	"(?:\\.[0-9]{3}(?:[0-9]{3}(?:[0-9]{3})?)?)"
#define REGEX_STR_TIME_HMS	"(?:" REGEX_STR_TIME_HOURS ":" REGEX_STR_TIME_MINUTES ":" REGEX_STR_TIME_SECONDS ")"

#define REGEX_STR_TIME_SPLIT_HMS	"(?:(" REGEX_STR_TIME_HOURS "):(" REGEX_STR_TIME_MINUTES "):(" REGEX_STR_TIME_SECONDS "))"

#define REGEX_STR_TIME_EPOCH	"(?:[12][0-9]{9}\\b)"
#define REGEX_STR_TIME_POSSIBLE_SUBSECS	"(?:" REGEX_STR_TIME_SUBSECS ")?"
//#define REGEX_STR_TIMESTAMP	"(?:(?:" REGEX_STR_TIME_HMS "|" REGEX_STR_TIME_EPOCH ")" REGEX_STR_TIME_POSSIBLE_SUBSECS ")"
//#define REGEX_STR_TIMESTAMP	"(?:(?:" REGEX_STR_TIME_SPLIT_HMS "|(" REGEX_STR_TIME_EPOCH "))(" REGEX_STR_TIME_POSSIBLE_SUBSECS ")?)"
#define REGEX_STR_TIMESTAMP	"(?:(?:(" REGEX_STR_TIME_HMS ")|(" REGEX_STR_TIME_EPOCH "))(" REGEX_STR_TIME_POSSIBLE_SUBSECS ")?)"
#define REGEX_STR_EXTRACT_TIMESTAMP "^(" REGEX_STR_TIMESTAMP ")\\s+(.+)$"

#define REGEX_STR_ELAPSED	"[0-9]+\\.[0-9]+"
#define REGEX_STR_EXTRACT_ELAPSED	"(.+)\\s+<(" REGEX_STR_ELAPSED ")>$"




//	'op_string' => '([a-zA-Z_][^\( ]+)', # going to assume we have at least 2 characters
//	'op_args_string' => '(.*?)',
//	'op_args_string' => '(.*?)',
//	'ret_string' => '(?:\s+= (.+?))',
//	'syscall' => qr/^$patterns{'op_string'}\($patterns{'op_args_string'}\)$patterns{'ret_string'}$/,
#define REGEX_STR_OP		"([a-zA-Z_][^\\( ]+)" /* going to assume we have at least 2 characters */
#define REGEX_STR_OP_ARGS	"(.*?)"
#define REGEX_STR_RET		"(?:\\s+= (.+?))"
#define REGEX_STR_SYSCALL	"^" REGEX_STR_OP "\\(" REGEX_STR_OP_ARGS "\\)" REGEX_STR_RET "$"
//#define REGEX_STR_
//#define REGEX_STR_
//#define REGEX_STR_
//#define REGEX_STR_
//#define REGEX_STR_
//#define REGEX_STR_
//#define REGEX_STR_
//#define REGEX_STR_
//#define REGEX_STR_

const char *regex_patterns[] = {
	[regex_extract_pid] = REGEX_STR_EXTRACT_PID,
	[regex_extract_timestamp] = REGEX_STR_EXTRACT_TIMESTAMP,
	[regex_extract_delay] = "",
	[regex_extract_elapsed] = REGEX_STR_EXTRACT_ELAPSED,
	[regex_split_syscall] = REGEX_STR_SYSCALL,
};
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
pcre *regexes[ARRAY_SIZE(regex_patterns)] = { 0 };

int extract_line(char *buf, int buf_bytes, char **line) {
	char *ptr = memchr(buf, '\n', buf_bytes);

	if (ptr == NULL)
		return 0;

	int len = ptr - buf;
	*line = strndup(buf, len);

	return len + 1;
}
int extract_line2(char *buf, int buf_bytes, char *line, bool eof) {
	char *ptr = memchr(buf, '\n', buf_bytes);
	int len;

	if (ptr)
		len = ptr - buf;
	else if (!eof)
		return 0;
	else // no newline and eof
		len = buf_bytes;

	memcpy(line, buf, len);
	line[len] = '\0';

	return len + 1;
}

typedef struct trace_entry_struct {
	pid_t pid;
	char *timestamp_str;
	char *delay_str;
	char *elapsed_str;
	char *ret_str;
	struct timespec timestamp;
	struct timespec delay;
	struct timespec elapsed;
	int timestamp_digits;
	int delay_digits;
	int elapsed_digits;
	int ret;
	char *syscall;
	char *args;
} trace_entry_t;


void print_groups(const char *line, int *ovector, int rc) {
	int i;

	for (i = 0 ; i < rc ; i++)
		output("  %d: %d bytes at offset %ld - %.*s\n",
			i, CAP_GROUP_LEN(ovector, i), CAP_GROUP_START(line, ovector, i) - line,
			CAP_GROUP_LEN(ovector, i), CAP_GROUP_START(line, ovector, i));
}
pid_t extract_pid(char *line) {
	int line_len = strlen(line);
	int ovector[OVECCOUNT] = { 0 }, rc;
	pid_t ret = -1;

	if ((rc = pcre_exec(regexes[regex_extract_pid], NULL,
			line, line_len, 0, /* start at offset 0 */
			0, /* default opts */
			ovector, ARRAY_SIZE(ovector))) < 0) {
		switch (rc) {
			case PCRE_ERROR_NOMATCH:
				output("no match\n");
				break;
			default:
				output("matching error %d\n", rc);
				break;
		}
		goto out;
	}

	ret = strtol(CAP_GROUP_START(line, ovector, 1), NULL, 10);
	memmove(line, CAP_GROUP_START(line, ovector, 3), CAP_GROUP_LEN(ovector, 3) + 1);
out:
	return ret;
}

unsigned long parse_subsec(const char *str) {
	unsigned long ret = 0;
	int gran = 9;

	while (*str != '\0') {
		ret *= 10;
		ret += (*str - '0');
		gran--;
		str++;
	}
	while (gran-- > 0)
		ret *= 10;
	return ret;
}
struct timespec parse_hms_subsec(const char *str) {
	struct timespec ts = { 0, 0 };
	char *ptr = NULL;
	int h, m, s;

	h = strtol(str, &ptr, 10);
	if (ptr && *ptr == ':') {
		str = ptr + 1;
		m = strtol(str, &ptr, 10);
		if (ptr && *ptr == ':') {
			str = ptr + 1;
			s = strtol(str, &ptr, 10);
			ts.tv_sec = (((s * 60) + m) * 60) + h;
			if (ptr && *ptr == '.')
				ts.tv_nsec = parse_subsec(ptr + 1);
		}
	}
	return ts;
}

struct timespec parse_seconds_subsec(const char *str) {
	struct timespec ts = { 0, 0 };
	char *ptr = NULL;

	ts.tv_sec = strtoul(str, &ptr, 10);
	if (*ptr == '.') {
		int gran = 9;
		ptr++;
		while (*ptr != '\0') {
			ts.tv_nsec *= 10;
			ts.tv_nsec += (*ptr - '0');
			gran--;
			ptr++;
		}
		while (gran-- > 0)
			ts.tv_nsec *= 10;
	}
	return ts;
}

struct timespec extract_timestamp(char *line) {
	int line_len = strlen(line);
	int ovector[OVECCOUNT] = { 0 }, rc;
	struct timespec ret = { 0, 0 };

	if ((rc = pcre_exec(regexes[regex_extract_timestamp], NULL,
			line, line_len, 0, /* start at offset 0 */
			0, /* default opts */
			ovector, ARRAY_SIZE(ovector))) < 0) {
		switch (rc) {
			case PCRE_ERROR_NOMATCH:
				output("no match for input string '%s'\n", line);
				break;
			default:
				output("matching error %d\n", rc);
				break;
		}
		goto out;
	}

	char *timestamp_str = strndup(CAP_GROUP_START(line, ovector, 1), CAP_GROUP_LEN(ovector, 1));

	output("timestamp string: %s\n", timestamp_str);

	if (CAP_GROUP_LEN(ovector, 2) > 0) {
			ret = parse_hms_subsec(timestamp_str);
	} else if (CAP_GROUP_LEN(ovector, 3) > 0) {
		ret = parse_seconds_subsec(timestamp_str);
	} else // no timestamp
		;

	free_mem(timestamp_str);
	print_groups(line, ovector, rc);

	memmove(line, CAP_GROUP_START(line, ovector, 5), CAP_GROUP_LEN(ovector, 5) + 1);
out:
	return ret;
}
struct timespec extract_elapsed(char *line) {
	int line_len = strlen(line);
	int ovector[OVECCOUNT] = { 0 }, rc;
	struct timespec ret = { 0, 0 };

	if ((rc = pcre_exec(regexes[regex_extract_elapsed], NULL,
			line, line_len, 0, /* start at offset 0 */
			0, /* default opts */
			ovector, ARRAY_SIZE(ovector))) < 0) {
		switch (rc) {
			case PCRE_ERROR_NOMATCH:
				output("no match for input string '%s'\n", line);
				break;
			default:
				output("matching error %d\n", rc);
				break;
		}
		goto out;
	}

print_groups(line, ovector, rc);

//	int matched_len = CAP_GROUP_LEN(ovector, 1);
	char *elapsed_str = strndup(CAP_GROUP_START(line, ovector, 2), CAP_GROUP_LEN(ovector, 2));

	output("elapsed string: %s\n", elapsed_str);

ret = parse_seconds_subsec(elapsed_str);

	free_mem(elapsed_str);

	line[CAP_GROUP_LEN(ovector, 1)] = '\0';

out:
	return ret;
}

int split_syscall_line(char *line, trace_entry_t *te) {
	int line_len = strlen(line);
	int ovector[OVECCOUNT] = { 0 }, rc;

output("split syscall:\n");
	if ((rc = pcre_exec(regexes[regex_split_syscall], NULL,
			line, line_len, 0, /* start at offset 0 */
			0, /* default opts */
			ovector, ARRAY_SIZE(ovector))) < 0) {
		switch (rc) {
			case PCRE_ERROR_NOMATCH:
				output("no match for input string '%s'\n", line);
				break;
			default:
				output("matching error %d\n", rc);
				break;
		}
		goto out;
	}
print_groups(line, ovector, rc);





out:
	return 42;
}





trace_entry_t *extract_metadata(char *line) {
	trace_entry_t *te = NULL;

	te = malloc(sizeof(trace_entry_t));
	memset(te, 0, sizeof(trace_entry_t));

	te->pid = extract_pid(line);

	output("pid: %d\n", te->pid);
	output("remainder: %s\n", line);


	te->timestamp = extract_timestamp(line);

	output("timestamp: %ld.%09ld\n", te->timestamp.tv_sec, te->timestamp.tv_nsec);
	output("remainder: %s\n", line);


	te->elapsed = extract_elapsed(line);
	output("elapsed: %ld.%09ld\n", te->elapsed.tv_sec, te->elapsed.tv_nsec);
	output("remainder: *%s*\n", line);



	return te;
}

int parse_line(char *line) {
	trace_entry_t *te = NULL;
	output("parsing:  %s\n", line);

	te = extract_metadata(line);
	split_syscall_line(line, te);

	output("\n");
}

int parse_lines(void *ptr, int fd) {
	int buf_bytes = 0;
	bool eof = false;
	char *buf = malloc(BUF_SIZE);
	char *line = malloc(BUF_SIZE);

	while (!eof) {
		int nread;

		if ((nread = read(fd, buf + buf_bytes, BUF_SIZE - buf_bytes - 1)) == 0)
			eof = true;
		else if (nread < 0) {
			output("Error reading from strace: %m\n");
			return EXIT_FAILURE;
		}
		buf_bytes += nread;

		if (buf_bytes) {
			int line_len;

			while ((line_len = extract_line2(buf, buf_bytes, line, eof)) > 0) {
				parse_line(line);

				memmove(buf, buf + line_len, buf_bytes - line_len);
				buf_bytes -= line_len;
			}

			if (eof && buf_bytes) {
				memcpy(line, buf, buf_bytes);
				line[buf_bytes] = '\0';
				parse_line(line);

				buf_bytes = 0;
			}
		}
	}
	free_mem(buf);
	free_mem(line);
}

int main(int argc, char *argv[]) {
	const char *error;
	int erroffset, i;

	for (i = 0 ; i < ARRAY_SIZE(regexes) ; i++) {
		if ((regexes[i] = pcre_compile(regex_patterns[i],
				0, /* default options */
				&error, &erroffset,
				NULL) /* use default character tables */ ) == NULL) {
			output("PCRE compilation of regex %d:\n\t%s\nfailed at offset %d: %s\n",
				i, regex_patterns[i], erroffset, error);
//			exit(1);
		}
	}

	int fd = -1;

	char *input_file_path = NULL;

	if (argc == 2) {
		input_file_path = strdup(argv[1]);
		if ((fd = openat(AT_FDCWD, input_file_path, O_RDONLY)) < 0) {
			output("could not open file: %m\n");
			return EXIT_FAILURE;
		}
	} else
		fd = fileno(stdin);


	return parse_lines(NULL, fd);




	return EXIT_SUCCESS;
}

