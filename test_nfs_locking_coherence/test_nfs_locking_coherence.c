/*
	Frank Sorenson <sorenson@redhat.com>, 2021
*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#define TEST_COUNT 10000
#define LOCAL_PATH "/exports/gcov_test/testfile"
#define NFS_PATH "/mnt/tmp2/gcov_test/testfile"

#define NSEC (1000000000ULL)

struct timespec ts_diff(const struct timespec ts1, const struct timespec ts2) {
	struct timespec ret, a, b;

	if ((ts1.tv_sec > ts2.tv_sec) ||
		((ts1.tv_sec == ts2.tv_sec) && (ts1.tv_nsec >= ts2.tv_nsec))) {
		a = ts1; b = ts2;
	} else {
		a = ts2; b = ts1;
	}
	ret.tv_sec = a.tv_sec - b.tv_sec - 1;
	ret.tv_nsec = a.tv_nsec - b.tv_nsec + NSEC;
	while (ret.tv_nsec >= NSEC) {
		ret.tv_sec ++;
		ret.tv_nsec -= NSEC;
	}
	return ret;
}

struct test_config_struct {
	struct flock rlock_fl;
	struct flock wlock_fl;
	struct flock unlock_fl;

	char *local_path;
	char *nfs_path;

	char *local_buf;
	char *nfs_buf;

	int local_fd;
	int nfs_fd;
} test_config = {
	.rlock_fl = {
		.l_type = F_RDLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0},
	.local_path = LOCAL_PATH,
	.nfs_path = NFS_PATH,
	.local_fd = -1,
	.nfs_fd = -1,
};

struct timespec do_one_test(bool do_writes) {
	struct timespec start_ts, stop_ts;
	int i;

	clock_gettime(CLOCK_REALTIME, &start_ts);
	for (i = 0 ; i < TEST_COUNT ; i++) {
		if (do_writes) {
			fcntl(test_config.local_fd, F_SETLK, &test_config.wlock_fl);
			write(test_config.local_fd, test_config.local_buf + i, 1);
			fcntl(test_config.local_fd, F_SETLK, &test_config.unlock_fl);
		}
		fcntl(test_config.nfs_fd, F_SETLK, &test_config.rlock_fl);
		read(test_config.nfs_fd, test_config.nfs_buf + i, 1);
		fcntl(test_config.nfs_fd, F_SETLK, &test_config.unlock_fl);
	}
	clock_gettime(CLOCK_REALTIME, &stop_ts);
	return ts_diff(start_ts, stop_ts);
}
void check_results(void) {
	int errors = 0, i;

	// check the results
	for (i = 0 ; i < TEST_COUNT ; i++)
		if (test_config.local_buf[i] != test_config.nfs_buf[i])
			errors++;
	printf("  detected %d errors\n", errors);
}

int reopen_nfs_file(void) {
	if (test_config.nfs_fd >= 0)
		close(test_config.nfs_fd);

	if ((test_config.nfs_fd = open(test_config.nfs_path, O_RDONLY)) < 0) {
		printf("failed to open nfs path '%s': %m\n", test_config.nfs_path);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
	struct timespec diff_ts;
	char this_char = 'A';
	int i;

	if (argc == 3) {
		test_config.local_path = argv[1];
		test_config.nfs_path = argv[2];
	}

	test_config.wlock_fl = test_config.unlock_fl = test_config.rlock_fl;
	test_config.wlock_fl.l_type = F_WRLCK;
	test_config.unlock_fl.l_type = F_UNLCK;

	test_config.local_buf = malloc(TEST_COUNT);
	test_config.nfs_buf = malloc(TEST_COUNT);

	if ((test_config.local_fd = open(test_config.local_path, O_RDWR|O_CREAT|O_TRUNC, 0660)) < 0) {
		printf("failed to open local path '%s': %m\n", test_config.local_path);
		return EXIT_FAILURE;
	}
	// allocate and fill the file with '*'
	fallocate(test_config.local_fd, 0, 0, TEST_COUNT);
	memset(test_config.local_buf, '*', TEST_COUNT);
	pwrite(test_config.local_fd, test_config.local_buf, TEST_COUNT, 0);

	// fill the write buffer
	for (i = 0 ; i < TEST_COUNT ; i++) {
		test_config.local_buf[i] = this_char;

		this_char++;
		if (this_char > 'Z')
			this_char = 'A';
	}


	// do writes & reads
	if (reopen_nfs_file() == EXIT_FAILURE)
		return EXIT_FAILURE;
	diff_ts = do_one_test(true);
	printf("%d writes and reads in %ld.%06ld seconds\n",
		TEST_COUNT, diff_ts.tv_sec, diff_ts.tv_nsec / 1000);
	check_results();

	if (reopen_nfs_file() == EXIT_FAILURE)
		return EXIT_FAILURE;
	diff_ts = do_one_test(false);
	printf("%d reads in %ld.%09ld seconds (open write file descriptor for local file)\n",
		TEST_COUNT, diff_ts.tv_sec, diff_ts.tv_nsec);


	close(test_config.local_fd);
	if (reopen_nfs_file() == EXIT_FAILURE)
		return EXIT_FAILURE;
	diff_ts = do_one_test(false);
	printf("%d reads in %ld.%09ld seconds (no open file descriptor for local file)\n",
		TEST_COUNT, diff_ts.tv_sec, diff_ts.tv_nsec);

	return EXIT_SUCCESS;
}
