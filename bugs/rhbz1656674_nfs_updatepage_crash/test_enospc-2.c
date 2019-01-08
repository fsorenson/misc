#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include <stdint.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#define mb()    __asm__ __volatile__("mfence" ::: "memory")
#define nop()   __asm__ __volatile__ ("nop")

#define RAND_STATE_SIZE 256
#define PROGRESS_FREQ 1000000
#define OUTPUT_PROGRESS 0

#define READER_COUNT 32
#define WRITER_COUNT 16

#define READ_EOF_RESTART 10000
#define WRITE_ENOSPC_RESTART 100

#define SHARED_RAND_STATE 1

#define MAX_IO 1024

struct shared_data_struct {
	struct random_data random_data;
	char *random_statebuf;

	char *filename;
};
struct shared_data_struct *shared_data;


void setup_random(void) {
	int ret;
#if SHARED_RAND_STATE
	shared_data->random_statebuf = mmap(NULL, RAND_STATE_SIZE, PROT_READ|PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
#else
	shared_data->random_statebuf = malloc(RAND_STATE_SIZE);
#endif
	memset(shared_data->random_statebuf, 0, RAND_STATE_SIZE);
	memset(&shared_data->random_data, 0, sizeof(shared_data->random_data));
	ret = initstate_r((time(NULL) % INT_MAX),
		shared_data->random_statebuf, RAND_STATE_SIZE,
		&shared_data->random_data);
	if (ret < 0) {
		printf("initstate_r (random initialization) returned %d: %m\n", errno);
	}
}
int pickanum(int _low, int _high) { /* both inclusive */
	int low, high;
	int spread;
	int r;
	int ret;

	if (_low < _high) { low = _low ; high = _high; }
	else { low = _high; high = _low; }

	spread = high - low;
	ret = random_r(&shared_data->random_data, &r);
	if (ret == -1) {
		printf("random_r returned %d: %m\n", errno);
	}
	return (r % (spread + 1)) + low;
}

int read_work1() {
	char *buf;
	int fd;

	size_t len;
	int ret;
#if OUTPUT_PROGRESS
	uint64_t read_count = 0;
	uint64_t read_progress = PROGRESS_FREQ;
#endif
	uint64_t eof_count = 0;

	buf = malloc(MAX_IO);

	while ((fd = open(shared_data->filename, O_RDONLY)) < 0)
		sleep(1);

	while (42) {
		len = pickanum(1, MAX_IO);
		ret = read(fd, buf, len);
		if (ret < 0) {
			printf("read returned %m\n");
		} else {
#if OUTPUT_PROGRESS
			read_count += ret;
			if (read_count >= read_progress) {
				uint64_t curpos = lseek(fd, 0, SEEK_CUR);
				printf("read: %lu, current pos: %lu\n", read_count, curpos);
				read_progress = read_progress + PROGRESS_FREQ;
			}
#endif
			if (ret == 0)
				eof_count++;
			if (eof_count > READ_EOF_RESTART) {
				eof_count = 0;
				lseek(fd, 0, SEEK_SET);
//printf("R");
//fflush(stdout);
#if OUTPUT_PROGRESS
				printf("read; eof %d times - restarting position\n", READ_EOF_RESTART);
#endif
			}
		}
	}
}

int write_work1() {
	int enospc_count;
	size_t len;
	char *buf;
	int ret;
	int fd;
#if OUTPUT_PROGRESS
	uint64_t write_count = 0;
	uint64_t write_progress = PROGRESS_FREQ;
#endif

	buf = malloc(MAX_IO);
	memset(buf, 0x55, MAX_IO);


	while ((fd = open(shared_data->filename, O_CREAT|O_TRUNC|O_RDWR, 0664)) < 0)
		sleep(1);
//		printf("error opening '%s': %m\n", shared_data->filename);
//		return EXIT_FAILURE;
//	}

	enospc_count = 0;

	while (42) {
		len = pickanum(1, MAX_IO);
		ret = write(fd, buf, len);
		if (ret < 0) {
			enospc_count++;
#if OUTPUT_PROGRESS
printf("***\n");
#endif
		} else {
//			printf("+\n");
//			fflush(stdout);
		}

#if OUTPUT_PROGRESS
		if (ret > 0)
			write_count += ret;
		if (write_count >= write_progress) {
			uint64_t curpos = lseek(fd, 0, SEEK_CUR);
			printf("write: %lu, current_pos: %lu\n", write_count, curpos);
			write_progress += PROGRESS_FREQ;
		}
#endif

		if (enospc_count > WRITE_ENOSPC_RESTART) {
			enospc_count = 0;
			lseek(fd, 0, SEEK_SET);
//			fsync(fd);
//printf("W");
//fflush(stdout);

#if OUTPUT_PROGRESS
			printf(".");
			fflush(stdout);
#endif
		} else {
		}
	}
}
int write_work2() {
	int enospc_count;
	size_t len;
	char *buf;
	int ret;
	int fd;
#if OUTPUT_PROGRESS
	uint64_t write_count = 0;
	uint64_t write_progress = PROGRESS_FREQ;
#endif

	buf = malloc(MAX_IO);
	memset(buf, 0x55, MAX_IO);
	while ((fd = open(shared_data->filename, O_CREAT|O_TRUNC|O_RDWR, 0664)) < 0)
		sleep(1);
//	if ((fd = open(shared_data->filename, O_CREAT|O_TRUNC|O_RDWR, 0664)) < 0) {
//		printf("error opening '%s': %m\n", shared_data->filename);
//		return EXIT_FAILURE;
//	}

	enospc_count = 0;

	while (42) {
		len = pickanum(1, MAX_IO);
		ret = write(fd, buf, len);
		if (ret < 0) {
			enospc_count++;
#if OUTPUT_PROGRESS
printf("***\n");
#endif
		} else {
//			printf("+\n");
//			fflush(stdout);
		}

#if OUTPUT_PROGRESS
		if (ret > 0)
			write_count += ret;
		if (write_count >= write_progress) {
			uint64_t curpos = lseek(fd, 0, SEEK_CUR);
			printf("write: %lu, current_pos: %lu\n", write_count, curpos);
			write_progress += PROGRESS_FREQ;
		}
#endif

		if (enospc_count > WRITE_ENOSPC_RESTART) {
			enospc_count = 0;
#if 0
			close(fd);
			if ((fd = open(shared_data->filename, O_CREAT|O_RDWR, 0664)) < 0) {
				printf("error opening '%s': %m\n", shared_data->filename);
				return EXIT_FAILURE;
			}
#else
			lseek(fd, 0, SEEK_SET);
			ftruncate(fd, 0);
			printf(".");
#endif

#if OUTPUT_PROGRESS
			printf(".");
			fflush(stdout);
#endif
		} else {
		}
	}
}




int main(int argc, char *argv[]) {
	pid_t cpid;
	int (*work[READER_COUNT + WRITER_COUNT])();
//	int *work();

	int i;

#if SHARED_RAND_STATE
	shared_data = mmap(NULL, sizeof(struct shared_data_struct),
		PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
#else // just malloc some space... doesn't need to be shared
	shared_data = malloc(sizeof(struct shared_data_struct));
#endif
	setup_random();


	shared_data->filename = "testfile";

	for (i = 0 ; i < READER_COUNT ; i++)
		work[i] = read_work1;
	for (i = READER_COUNT ; i < READER_COUNT + WRITER_COUNT ; i++)
		work[i] = write_work1;

	for (i = 0 ; i < READER_COUNT + WRITER_COUNT - 1 ; i++)
		if ((cpid = fork()) == 0)
			return work[i]();
	return work[i]();
}
