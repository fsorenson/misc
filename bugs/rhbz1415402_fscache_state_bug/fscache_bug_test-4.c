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

#define SLEEP_MIN_NS (200ULL)
#define SLEEP_MAX_NS (700ULL)
#define SLEEP_INCR (100ULL)


#define mb()    __asm__ __volatile__("mfence" ::: "memory")
#define nop()   __asm__ __volatile__ ("nop")


struct shared_data_struct {
	char **filenames;
	volatile int go;

	int file_num;

} *shared_data;


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
	int fd;
	char *buf;
	int block_i;

	buf = malloc(BLOCK_SIZE);

	while (1) {
		while (shared_data->go)
			nop();

		shared_data->file_num = (shared_data->file_num + 1) % NUM_TESTFILES;

		shared_data->go = 1;
		mb();
		fd = open(shared_data->filenames[shared_data->file_num], O_RDONLY);

		for (block_i = 0 ; block_i < (TESTFILE_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE ; block_i++)
			read(fd, buf, BLOCK_SIZE);
		close(fd);
	}
}

void do_rw_opens() {
	int fd;
	struct timespec ts;

	ts.tv_sec = 0;
	ts.tv_nsec = SLEEP_MIN_NS;

	while (! shared_data->go)
		nop();
	shared_data->go = 0;
	mb();
	while (1) {
		while (! shared_data->go)
			nop();

		nanosleep(&ts, NULL);

		fd = open(shared_data->filenames[shared_data->file_num], O_RDWR);
		close(fd);

		ts.tv_nsec += SLEEP_INCR;
		if (ts.tv_nsec > SLEEP_MAX_NS)
			ts.tv_nsec = SLEEP_MIN_NS;

		shared_data->go = 0;
		mb();
	}
}


int main(int argc, char *argv[]) {
	pid_t cpid;

	shared_data = mmap(NULL, sizeof(struct shared_data_struct),
		PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	printf("Creating files\n");
	create_files();

	printf("Starting O_RDWR thread and beginning reads\n");
	if ((cpid = fork()) > 0) { /* parent process */
		do_reads();
	} else {
		do_rw_opens();
	}

	return EXIT_SUCCESS;
}
