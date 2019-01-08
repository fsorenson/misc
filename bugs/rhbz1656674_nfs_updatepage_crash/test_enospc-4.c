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

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define MAX_IO (4ULL * KiB)


// *****
#define READER_COUNT 8
#define WRITER_COUNT 4
#define MAX_FILE_SIZE (100ULL * MiB)
// *****


#define MAX_FILE_PAGE ((MAX_FILE_SIZE + 4095ULL) / 4096ULL)
#define RAND_STATE_SIZE 256

struct shared_data_struct {
	struct random_data random_data;
	char random_statebuf[RAND_STATE_SIZE];

	char *filename;
	long current_page;
	long min_page;
};
struct shared_data_struct *shared_data;

void setup_random(void) {
	int ret;

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

int read_work() {
	off_t offset;
	size_t len;
	char *buf;
	int fd;

	buf = malloc(MAX_IO);
	while ((fd = open(shared_data->filename, O_RDONLY, 0664)) < 0)
		sleep(1);

	while (42) {
		len = pickanum(1, MAX_IO);
		offset = pickanum(0, MAX_IO - len);

		offset += shared_data->current_page * 4096;
		pread(fd, buf, len, offset);
	}
}
int write_work() {
	off_t offset;
	size_t len;
	char *buf;
	int fd;

	buf = malloc(MAX_IO);
	memset(buf, 0x55, MAX_IO);
	while ((fd = open(shared_data->filename, O_RDWR)) < 0)
		sleep(1);

	while (42) {
		len = pickanum(1, MAX_IO);
		offset = pickanum(0, MAX_IO - len);

		offset += shared_data->current_page * 4096;
		pwrite(fd, buf, len, offset);
	}
}

int director_work() {
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000 };

	while (42) {
		shared_data->current_page = pickanum(0, MAX_FILE_PAGE - 1);
		mb();
		nanosleep(&ts, NULL);
	}
}
int director_work2() {
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000 };
	long tmp_current;

//	shared_data->current_page = shared_data->min_page + 1;

	tmp_current = shared_data->min_page + 1;
	while (42) {
//		shared_data->current_page = pickanum(0, MAX_FILE_PAGE - 1);
		shared_data->current_page = tmp_current;
		mb();
		printf(".");
		fflush(stdout);
		nanosleep(&ts, NULL);

		tmp_current++;
		if (tmp_current > MAX_FILE_PAGE - 1)
			tmp_current = shared_data->min_page + 1;
	}

}
int initial_fill(void) {
	int enospc_count = 0;
	int ret = EXIT_FAILURE;
	char *buf;
	int fd;

	buf = malloc(4096);

	if ((fd = open(shared_data->filename, O_CREAT|O_TRUNC|O_RDWR|O_SYNC, 0664)) < 0) {
		printf("unable to open '%s': %m\n", shared_data->filename);
		goto out;
	}

	while (enospc_count < 10) {
		shared_data->min_page++;
		if (((write(fd, buf, 4096)) < 0) && (errno == ENOSPC))
			enospc_count++;
	}
	ret = EXIT_SUCCESS;

	close(fd);
out:
	free(buf);
out_nomem:
	return ret;
}

int main(int argc, char *argv[]) {
	pid_t cpid;
	int i;

	shared_data = mmap(NULL, sizeof(struct shared_data_struct),
		PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	setup_random();

	shared_data->filename = "testfile";
	if (initial_fill() == EXIT_FAILURE)
		return EXIT_FAILURE;

	for (i = 0 ; i < WRITER_COUNT ; i++)
		if ((cpid = fork()) == 0)
			return write_work();

	for (i = 0 ; i < READER_COUNT ; i++)
		if ((cpid = fork()) == 0)
			return read_work();

//	return director_work();
	return director_work2();
}
