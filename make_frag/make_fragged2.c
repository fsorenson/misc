/*
	Frank Sorenson <sorenson@redhat.com>, 2024

	Create a badly-fragmented file

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <getopt.h>

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)
#define TiB (KiB * KiB * KiB * KiB)

#define BLOCK_SIZE (4 * KiB)
#define FILE_SIZE (1 * TiB)
#define NUM_BLOCKS (FILE_SIZE / BLOCK_SIZE)

#define TESTPATH "/mnt/tmp"
#define TESTFILE "testfile"
#define STATEFILE TESTFILE ".state"

#define RAND_STATE_SIZE 256

enum create_mode { mode_create, mode_continue };
struct run_data {
	enum create_mode create_mode;
	int fd;
	int dfd;
	int state_fd;
	char *test_dir;
	char *test_file;
	char *state_file;
	uint64_t file_size;
	uint32_t block_size;
	uint32_t num_blocks;
	uint32_t state_size;

	struct random_data random_data;
	char random_state[RAND_STATE_SIZE];
} run_data = {
	.test_dir = TESTPATH,
	.test_file = TESTFILE,
	.file_size = FILE_SIZE,
	.block_size = BLOCK_SIZE,
};

struct state_data {
	uint64_t file_size;
	uint32_t block_size;
	uint32_t num_blocks;
	uint32_t remaining_blocks;
	uint32_t filler[11];
	uint32_t blocks[];
};
struct state_data *state_data;

/* returns a size in bytes */
uint64_t parse_size(const char *size_str) {
	uint64_t uint_size = 0, ret;
	long double size;
	int shift = 0, have_uint = 0;
	char *p;

	uint_size = strtoull(size_str, NULL, 10);
	size = strtold(size_str, &p);

	if (fabsl((long double)uint_size - size) < 1e-9)
		have_uint = 1; /* integer, or close enough */

	while (*p != '\0' && (*p == '.' || *p == ' '))
		p++;
	if (*p != '\0') {
		if (strlen(p) <= 3) {
			if (strlen(p) == 2 && tolower(*(p+1)) != 'b')
				goto out_badsize;
			else if (strlen(p) == 3 &&
				(tolower(*(p+1)) != 'i' || tolower(*(p+2)) != 'b'))
				goto out_badsize;

			switch (tolower(*p)) {
				/* can't actually represent these */
				case 'y':
				case 'z':
					printf("size too large: %s\n", p);
					return 0;
					break;
				case 'e': shift++;
				case 'p': shift++;
				case 't': shift++;
				case 'g': shift++;
				case 'm': shift++;
				case 'k':
					shift++;
					break;
				default:
					goto out;
					break;
			}
		} else
			goto out_badsize;
	}
	if (have_uint && shift)
		ret = uint_size * (1ULL << (shift * 10));
	else if (have_uint)
		ret = uint_size;
	else if (shift)
		ret = (uint64_t)(size * (long double)(1ULL << (shift * 10)));
	else
		ret = uint_size; /* might as well be an integer */
out:
	return ret;

out_badsize:
	printf("unrecognized size: '%s'\n", p);
	return 0;
}

int pickanum(int _low, int _high) { /* both inclusive */
	int low, high;
	int spread;
	int r;

	if (_low < _high) { low = _low ; high = _high; }
	else { low = _high; high = _low; }

	spread = high - low;
	random_r(&run_data.random_data, &r);
	return (r % (spread + 1)) + low;
}

void print_pct(uint64_t progress, uint64_t total) {
	long double pct = (long double)progress / (long double)total * 100.0;
	printf("%10" PRIu64 " / %10" PRIu64 ": %.04Lf%%   \r",
		progress, total, pct);
}

void randomize_blocks(void) {
	uint32_t remaining, i;
	uint64_t blocks_size = sizeof(uint32_t) * state_data->num_blocks;
	uint32_t *blocks;

	blocks = malloc(blocks_size);

	remaining = state_data->num_blocks;

	initstate_r(time(NULL) % INT_MAX, run_data.random_state, RAND_STATE_SIZE, &run_data.random_data);

	printf("randomizing %u blocks\n", state_data->num_blocks);

	for (i = 0 ; i < state_data->num_blocks ; i++)
		blocks[i] = i;

	while (remaining) {
		uint32_t this_rand = pickanum(0, remaining - 1);
		uint32_t tmp = blocks[this_rand];
		blocks[this_rand] = blocks[remaining - 1];
		blocks[remaining - 1] = tmp;

		remaining--;
		if ((remaining % 100) == 0)
			print_pct(state_data->num_blocks - remaining, state_data->num_blocks);
	}
	printf("randomized... writing random sequence to state file\n");
	memcpy(state_data->blocks, blocks, blocks_size);
	printf("random block sequence written to state file\n");

	free(blocks);
}

int usage(const char *exe, int ret) {
	printf("usage: %s [ ... options ... ]\n", exe);
	printf("\t[-s | --size <size>] - specify the size of the fragmented file to create\n");
	printf("\t[-b | --block_size <size>] - specify the size of blocks to allocate\n");
	printf("\t[-d | --dir <directory>] - create the file in this directory\n");
	printf("\t[-f | --filename <filename>] - name of file to create\n");

	return ret;
}

int parse_opts(int argc, char *argv[]) {
	int opt = 0, long_index = 0;
	static struct option long_options[] = {
		{ "size", required_argument, 0, 's' },
		{ "block_size", required_argument, 0, 'b' },
		{ "dir", required_argument, 0, 'd' },
		{ "filename", required_argument, 0, 'f' },
		{ "help", no_argument, 0, 'h' },
		
		{ NULL, 0, 0, 0 }
	};

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "s:b:d:f:h", long_options, &long_index)) != -1) {
		switch (opt) {
			case 's':
				run_data.file_size = parse_size(optarg); break;
			case 'b':
				run_data.block_size = parse_size(optarg); break;
			case 'd':
				run_data.test_dir = strdup(optarg); break;
			case 'f':
				run_data.test_file = strdup(optarg); break;
			default:
				printf("unknown opt: %c\n", opt);
			case 'h':
				return usage(argv[0], EXIT_FAILURE);
				break;
		}
	}
	asprintf(&run_data.state_file, "%s.state", run_data.test_file);

	return 0;
}

int setup_new(void) {
	run_data.num_blocks = run_data.file_size / run_data.block_size;

	printf("fragmenting file of size %" PRIu64 " at %s/%s (state file: %s/%s) with block size %u\n",
		run_data.file_size, run_data.test_dir, run_data.test_file, run_data.test_dir, run_data.state_file, run_data.block_size);

	run_data.state_size = sizeof(struct state_data) + (sizeof(uint32_t) * run_data.num_blocks);

	unlinkat(run_data.dfd, run_data.state_file, 0);
	unlinkat(run_data.dfd, run_data.test_file, 0);
	if ((run_data.state_fd = openat(run_data.dfd, run_data.state_file, O_CREAT|O_TRUNC|O_RDWR, 0664)) < 0) {
		printf("error creating/opening state file: %m\n");
		return EXIT_FAILURE;
	}
	if (ftruncate(run_data.state_fd, run_data.state_size)) {
		printf("error creating state file with size %u: %m\n", run_data.state_size);
		return EXIT_FAILURE;
	}
	if (fallocate(run_data.state_fd, 0, 0, run_data.state_size) < 0) {
		printf("error allocating space for the state file: %m\n");
		return EXIT_FAILURE;
	}

	if ((state_data = mmap(0, run_data.state_size, PROT_READ|PROT_WRITE, MAP_SHARED, run_data.state_fd, 0)) == MAP_FAILED) {
		printf("failed to mmap state file: %m\n");
		return EXIT_FAILURE;
	}
	state_data->file_size = run_data.file_size;
	state_data->block_size = run_data.block_size;
	state_data->num_blocks = run_data.num_blocks;
	state_data->remaining_blocks = state_data->num_blocks;

	randomize_blocks();

	if ((run_data.fd = openat(run_data.dfd, run_data.test_file, O_CREAT|O_TRUNC|O_WRONLY, 0664)) < 0) {
		printf("error creating/opening test file '%s/%s': %m\n", run_data.test_dir, run_data.test_file);
		return EXIT_FAILURE;
	}
	if (ftruncate(run_data.fd, state_data->file_size)) {
		printf("error truncating test file to %" PRIu64 "\n", state_data->file_size);
		return EXIT_FAILURE;
	}
	printf("beginning allocations\n");

	return EXIT_SUCCESS;
}

int setup_existing(void) {
	struct stat st;

	printf("test and state files exist... continuing\n");
	if ((run_data.state_fd = openat(run_data.dfd, run_data.state_file, O_RDWR)) < 0) {
		printf("error opening state file: %m\n");
		return EXIT_FAILURE;
	}
	fstat(run_data.state_fd, &st);
	run_data.state_size = st.st_size;
	if (run_data.state_size <= sizeof(struct state_data)) { // must have at least *some* blocks
		printf("size of existing state file too small to hold meaningful state\n");
		return EXIT_FAILURE;
	}
	if ((state_data = mmap(0, run_data.state_size, PROT_READ|PROT_WRITE, MAP_SHARED, run_data.state_fd, 0)) == MAP_FAILED) {
		printf("failed to mmap state file: %m\n");
		return EXIT_FAILURE;
	}
	if (state_data->num_blocks != state_data->file_size / state_data->block_size) {
		printf("number of blocks in state (%u) does not match expected count (%lu)\n",
			state_data->num_blocks, state_data->file_size / state_data->block_size);
		return EXIT_FAILURE;
	}
	if (run_data.state_size != sizeof(struct state_data) + (sizeof(uint32_t) * state_data->num_blocks)) {
		printf("state size (%u) does not match expected size (%lu)\n",
			run_data.state_size, sizeof(struct state_data) + (sizeof(uint32_t) * state_data->num_blocks));
		return EXIT_FAILURE;
	}

	printf("fragmenting file of size %" PRIu64 " at %s/%s (state file: %s/%s) with block size %u\n",
		state_data->file_size, run_data.test_dir, run_data.test_file, run_data.test_dir, run_data.state_file, state_data->block_size);

	if ((run_data.fd = openat(run_data.dfd, run_data.test_file, O_WRONLY)) < 0) {
		printf("error opening test file: %m\n");
		return EXIT_FAILURE;
	}
	fstat(run_data.fd, &st);
	if (st.st_size != state_data->file_size) {
		printf("test file size (%" PRIu64 ") does not match expected file size (%" PRIu64 ")\n",
			st.st_size, state_data->file_size);
		return EXIT_FAILURE;
	}

	printf("resuming allocations\n");
	return EXIT_SUCCESS;
}

void frag_file(void) {
	while (state_data->remaining_blocks) {
		uint32_t this_block = state_data->blocks[state_data->remaining_blocks - 1];

		fallocate(run_data.fd, FALLOC_FL_KEEP_SIZE|FALLOC_FL_ZERO_RANGE, this_block * BLOCK_SIZE, BLOCK_SIZE);
		state_data->remaining_blocks--;
		if ((state_data->remaining_blocks % 100) == 0)
			print_pct(state_data->num_blocks - state_data->remaining_blocks, state_data->num_blocks);
	}
}

int main(int argc, char *argv[]) {
	struct stat st;

	if (parse_opts(argc, argv))
		return EXIT_FAILURE;

	run_data.create_mode = mode_create;

	if ((run_data.dfd = open(run_data.test_dir, O_DIRECTORY|O_RDONLY)) < 0) {
		printf("error opening test directory '%s': %m\n", run_data.test_dir);
		return EXIT_FAILURE;
	}

	if (!fstatat(run_data.dfd, run_data.test_file, &st, 0) && !fstatat(run_data.dfd, run_data.state_file, &st, 0))
		run_data.create_mode = mode_continue;

	if (run_data.create_mode == mode_create) {
		if (setup_new())
			return EXIT_FAILURE;
	} else
		if (setup_existing())
			return EXIT_FAILURE;

	printf("file size: %" PRIu64 "\n", state_data->file_size);
	printf("block size: %u\n", state_data->block_size);
	printf("num blocks: %u\n", state_data->num_blocks);

	frag_file();
	printf("\n");

	return EXIT_SUCCESS;
}
