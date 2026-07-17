#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <dirent.h>

#define DEFAULT_NUM_THREADS 6
#define DIRENT_BUF 65536

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define free_buf(x) do { \
	if (x) \
		free(x); \
	x = NULL; \
} while (0)
#define close_fd(x) do { \
	if (x >= 0) \
		close(x); \
	x = -1; \
} while (0)

int read_dir(const char *path) {
	struct dirent *de;
	char *dirent_buf = NULL, *bpos;
	int dfd = -1, ret = EXIT_SUCCESS, nread;

	dirent_buf = malloc(DIRENT_BUF);
	if ((dfd = open(path, O_DIRECTORY)) < 0) {
		output("error opening directory '%s': %m\n", path);
		goto out;
	}
	while (42) {
		if ((nread = syscall(SYS_getdents64, dfd, dirent_buf, DIRENT_BUF)) < 0) {
			output("getdents call failed: %m\n");
			goto out;
		}
		if (nread == 0)
			break;

		bpos = dirent_buf;
		while (bpos < dirent_buf + nread) {
			de = (struct dirent *)bpos;
			bpos += de->d_reclen;

			// don't really do anything with the files
		}
	}
	ret = EXIT_SUCCESS;
out:
	close_fd(dfd);
	free_buf(dirent_buf);

	return ret;
}

int process_one(int threadnum, int filenum) {
	int fd = -1;
	char *filename1 = NULL, *filename2 = NULL, buf[4096];
	struct stat st1, st2;
	int ret = EXIT_FAILURE;

	memset(buf, 'X', sizeof(buf));

	asprintf(&filename1, "work/file_%d_%d.xml__temp", threadnum, filenum); // work/file_1_1.xml__temp
	asprintf(&filename2, "work/file_%d_%d.xml", threadnum, filenum); // work/file_1_1.xml

	// cleanup/setup
	unlink(filename1);
	unlink(filename2);

	if ((fd = open(filename1, O_CREAT|O_TRUNC|O_RDWR, 0644)) < 0) { // work/file_1_1.xml__temp
		output("error opening %s: %m\n", filename1);
		goto out;
	}
	write(fd, buf, 1290);
	close_fd(fd); // work/file_1_1.xml__temp

	stat(filename1, &st1); // work/file_1_1.xml__temp
	if (rename(filename1, filename2) < 0) { // work/file_1_1.xml__temp, work/file_1_1.xml
		output("error renaming %s -> %s: %m\n", filename1, filename2);
		goto out;
	}
	stat(filename2, &st2); // work/file_1_1.xml
	if ((intmax_t)st1.st_size != (intmax_t)st2.st_size) {
		output("file size of '%s' prior to rename: %ld, file size of '%s' after rename: %ld\n", filename1, (intmax_t)st1.st_size, filename2, (intmax_t)st2.st_size);
		goto out;
	}


//	read_dir("work");
	read_dir("work");

	ret = EXIT_SUCCESS;
out:
	close_fd(fd);
	free_buf(filename1); // work/file_1_1.xml__temp
	free_buf(filename2); // work/file_1_1.xml

	return ret;
}

typedef struct {
	int threadnum;
	int filenum;
	int result;
} thread_data_t;

void* thread_wrapper(void *arg) {
	thread_data_t *data = (thread_data_t *)arg;
	data->result = process_one(data->threadnum, data->filenum);
	return NULL;
}

int main(int argc, char *argv[]) {
	int num_threads = DEFAULT_NUM_THREADS;
	thread_data_t *thread_data;
	pthread_t *threads;
	char *test_path = argv[1];
	int failed_count = 0;
	int filenum, i;

	if (argc == 4) {
		filenum = strtol(argv[2], NULL, 10);
		num_threads = strtol(argv[3], NULL, 10);
	} else if (argc == 3) {
		filenum = strtol(argv[2], NULL, 10);
	} else if (argc == 2) {
		filenum = 0;
	} else {
		output("Usage: %s <test_path> [<filenum> [<num_threads>]]\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (chdir(test_path) < 0) {
		output("error changing to test path %s: %m\n", test_path);
		return EXIT_FAILURE;
	}
	if (mkdir("work", 0755) < 0 && errno != EEXIST) {
		output("error creating 'work' subdir: %m\n");
		return EXIT_FAILURE;
	}

	threads = malloc(num_threads * sizeof(pthread_t));
	thread_data = malloc(num_threads * sizeof(thread_data_t));
	for (i = 0; i < num_threads ; i++) {
		thread_data[i].threadnum = i;
		thread_data[i].filenum = filenum;
		thread_data[i].result = EXIT_FAILURE;

		if (pthread_create(&threads[i], NULL, thread_wrapper, &thread_data[i]) != 0) {
			output("Error creating thread %d\n", i);
			return EXIT_FAILURE;
		}
	}

	// Reap all threads
	for (i = 0; i < num_threads ; i++) {
		pthread_join(threads[i], NULL);
		if (thread_data[i].result != EXIT_SUCCESS) {
			failed_count++;
		}
	}

	// Report results
	if (failed_count > 0) {
		output("FAILED: %d out of %d threads failed\n", failed_count, num_threads);
		return EXIT_FAILURE;
	} else {
		output("SUCCESS: All %d threads completed successfully\n", num_threads);
		return EXIT_SUCCESS;
	}
}
