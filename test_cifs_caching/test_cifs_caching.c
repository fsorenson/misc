/*
	Frank Sorenson <sorenson@redhat.com>, 2024

	test cifs cache=* behavior

	RHEL 7 has a bug whereby when reading from a file that is
	undergoing file-extending writes, the file becomes corrupted,
	and contains null bytes for the latter portion of a page

	The bug only appears to occur when 'cache=strict'; not reported
	with 'cache=none' or 'cache=loose'


	this test program will replicate the bug in two processes, both
		operating on the same file:
	  1) opens, repeatedly writes blocks of (8192-32) bytes of
		non-null data ('A') to a fill point, closes, then repeats
	  2) repeatedly opens, reads, and searches for null-byte values
		in the file, closes the file
	if thread 2 finds null bytes, both processes stop


	# gcc -Wall test_cifs_caching.c -o test_cifs_caching

	sample output from several runs (random-size writes):
	  null bytes from offset 36867718 for length 378
	  null bytes from offset 15857352 for length 2360
	  null bytes from offset 176770679 for length 393
	  null bytes from offset 33677323 for length 4085

	(note: all null-byte blocks occupy the latter portion of a 4 KiB
		block, ending on the boundary)


	time to replicate is varied; anywhere from 11 seconds
		to 29 minutes have been seen
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define mb()    __asm__ __volatile__("mfence" ::: "memory")

#define KiB (1024ULL)
#define MiB (KiB * KiB)

#define OUTBUF_SIZE 8192
#define WRITE_SIZE (OUTBUF_SIZE - 32)
#define CHECKER_BUF_SIZE (MiB)

#define FILE_SIZE (50ULL * MiB)

#define DEBUG 1

struct test_state {
	pid_t cpid;
	bool exit;
	bool found_nulls;
	char *filename;

	/* writer */
	char *outbuf;

	/* checker */
	char *checkbuf;
} *test_state;

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)
#define debug_output(args...) do { \
	if (DEBUG) \
		output(args); \
} while (0)

/* writer portion */

void write_one_file(void) {
	int fd, current_size = 0;

	debug_output("W");

	if ((fd = open(test_state->filename, O_RDWR|O_CREAT|O_TRUNC, 0666)) < 0) {
		output("error opening file: %m\n");
		test_state->exit = true;
		return;
	}

	while (current_size < FILE_SIZE) {
		write(fd, test_state->outbuf, WRITE_SIZE);
		current_size += WRITE_SIZE;

		if (test_state->exit) /* child found nulls? */
			break;
	}
	close(fd);
}

/* checker portion */

typedef enum { in_data, in_nulls } segment_type;

void check_once(void) {
	int read_offset = 0, null_byte_start_offset = 0;
	int fd, bytes_read, null_segment_count = 0;
	segment_type current_segment_type = in_data;
	char *p, *q;

	debug_output("C");

retry_open:
	if (test_state->exit)
		return;
	if ((fd = open(test_state->filename, O_RDONLY)) < 0) {
		output("error opening file: %m\n");
		if (errno == ENOENT) {
			sleep(2);
			output("trying again\n");
			goto retry_open;
		}
		test_state->exit = true;
		return;
	}

	while ((bytes_read = read(fd, test_state->checkbuf, CHECKER_BUF_SIZE)) > 0) {
		p = test_state->checkbuf;
		while (p < test_state->checkbuf + bytes_read) {
			if (current_segment_type == in_data) {
				if ((q = memchr(p, '\0', bytes_read - (p - test_state->checkbuf))) != NULL) {
					null_byte_start_offset = read_offset + q - test_state->checkbuf;
					current_segment_type = in_nulls;
					null_segment_count++;
					test_state->found_nulls = true;
					test_state->exit = true;
					mb();
					p = q;
				} else
					break;
			} else {
				while (p < test_state->checkbuf + bytes_read && *p == '\0')
					p++;
				if (p < test_state->checkbuf + bytes_read && *p != '\0') { /* found a non-null */
					int null_byte_end_offset = read_offset + p - test_state->checkbuf;

					output("null bytes from offset %d for length %d\n",
						null_byte_start_offset,
						null_byte_end_offset - null_byte_start_offset);
					current_segment_type = in_data;
					null_byte_start_offset = 0;
				}
			}
		}
		read_offset += bytes_read;
	}
	if (bytes_read >= 0 && current_segment_type == in_nulls) { /* ended in nulls */
		output("null bytes from offset %d for length %d\n",
			null_byte_start_offset,
			read_offset - null_byte_start_offset);
	}
	if (bytes_read < 0)
		output("error reading: %m\n");

	if (null_segment_count)
		output("found %d null segments\n", null_segment_count);

	close(fd);
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		output("usage: %s <testfile>\n", argv[0]);
		return EXIT_FAILURE;
	}

	test_state = mmap(NULL, sizeof(struct test_state), PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	memset(test_state, 0, sizeof(struct test_state));

	test_state->filename = argv[1];

	if ((test_state->cpid = fork()) > 0) { /* parent process */
		test_state->outbuf = malloc(OUTBUF_SIZE);
		memset(test_state->outbuf, 'A', OUTBUF_SIZE);

		while (! test_state->exit)
			write_one_file();
		waitpid(test_state->cpid, NULL, 0);
		output("writer exiting\n");
	} else if (test_state->cpid == 0) { /* child process */
		test_state->checkbuf = malloc(CHECKER_BUF_SIZE);
		nice(-10);
		while (! test_state->exit)
			check_once();
		output("checker exiting\n");
	} else
		output("failed to fork: %m\n");
	return test_state->found_nulls ? EXIT_SUCCESS : EXIT_FAILURE;
}
