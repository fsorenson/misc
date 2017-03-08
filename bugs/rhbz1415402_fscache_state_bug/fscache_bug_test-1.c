#ifndef _GNU_SOURCE
#define _GNU_SOURCE 
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>



#define KiB (1024ULL)
#define MiB (KiB * KiB)

#define NUM_TESTFILES 100
#define TESTFILE_SIZE (10ULL * MiB)
#define BLOCK_SIZE (1ULL * MiB)
#define FILENAME_PATTERN "fscache_test_file-%d"

#define RAND_STATE_SIZE 256

//char **filenames[NUM_TESTFILES];

struct shared_data_struct {
	char **filenames;
	struct random_data random_data;
	char *random_statebuf;

} *shared_data;

int pickanum(int _low, int _high) { /* both inclusive */
	int low, high;
	int spread;
	int r;

	if (_low < _high) { low = _low ; high = _high; }
	else { low = _high; high = _low; }

	spread = high - low;
	random_r(&shared_data->random_data, &r);
	return (r % (spread + 1)) + low;
}


void create_files() {
	int fd;
	int file_i;
	char *buf;
	int block_i;

	shared_data->filenames = malloc(NUM_TESTFILES * sizeof(char *));
	buf = malloc(BLOCK_SIZE);
	memset(buf, 0xaa, BLOCK_SIZE);
	for (file_i = 0 ; file_i < NUM_TESTFILES ; file_i++) {
		asprintf(&shared_data->filenames[file_i], FILENAME_PATTERN, file_i);

		fd = open(shared_data->filenames[file_i], O_WRONLY|O_CREAT|O_TRUNC, 0644);
		for (block_i = 0 ; block_i < (TESTFILE_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE ; block_i++) {
			write(fd, buf, BLOCK_SIZE);
		}
		close(fd);
	}
	free(buf);
}

void do_reads() {
	int file_num;
	int fd;
	char *buf;
	int block_i;

	buf = malloc(BLOCK_SIZE);

	while (1) {
		file_num = pickanum(0, NUM_TESTFILES - 1);
		fd = open(shared_data->filenames[file_num], O_RDONLY);

		for (block_i = 0 ; block_i < (TESTFILE_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE ; block_i++)
			read(fd, buf, BLOCK_SIZE);

		close(fd);
	}
}

void do_rw_opens() {
	int file_num;
	int fd;

	while (1) {
		file_num = pickanum(0, NUM_TESTFILES - 1);
		fd = open(shared_data->filenames[file_num], O_RDWR);

		close(fd);
	}
}


int main(int argc, char *argv[]) {
	pid_t cpid;

	shared_data = mmap(NULL, sizeof(struct shared_data_struct),
		PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	shared_data->random_statebuf = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE,
		-1, 0);
	initstate_r((time(NULL) % INT_MAX),
		shared_data->random_statebuf, RAND_STATE_SIZE,
		&shared_data->random_data);

	create_files();

	if ((cpid = fork()) > 0) { /* parent process */
		do_reads();
	} else {
		do_rw_opens();
	}

	return EXIT_SUCCESS;
}
