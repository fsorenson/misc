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
#define DEFAULT_NUM_THREADS 6

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

int process_one(int threadnum, int filenum) {
	int fd0 = -1, fd1 = -1, fd2 = -1, fd3 = -1;
	char *filename0 = NULL, *filename1 = NULL, *filename2 = NULL, *filename3 = NULL, *filename4 = NULL, *filename5 = NULL, buf[4096];
	struct stat st1, st2;
	int ret = EXIT_FAILURE;
	int count;

	memset(buf, 'X', sizeof(buf));

	asprintf(&filename0, "work/file_%d_%d.xml.stringreplace.zip", threadnum, filenum); // work/file_1_1.xml_stringreplace.zip
	asprintf(&filename1, "file_%d_%d.xml", threadnum, filenum); // file_1_1.xml
	asprintf(&filename2, "work/file_%d_%d.xml__temp", threadnum, filenum); // work/file_1_1.xml__temp
	asprintf(&filename3, "work/file_%d_%d.xml", threadnum, filenum); // work/file_1_1.xml
	asprintf(&filename4, "work/file_%d_%d.xml_checkxsltmerge.zip", threadnum, filenum); // work/file_1_1.xml_checkxsltmerge.zip
	asprintf(&filename5, "work/file_%d_%d.xml.tmp", threadnum, filenum); // work/file_1_1.xml.tmp

	// cleanup/setup
	unlink(filename0);
	if ((fd0 = open(filename1, O_CREAT|O_TRUNC|O_WRONLY, 0644)) < 0) { // file_1_1.xml
		output("failed creating test file %s: %m\n", filename1);
		goto out;
	}
	write(fd0, buf, 1290);
	close_fd(fd0);
	unlink(filename2);
	unlink(filename3);
	unlink(filename4);
	unlink(filename5);

	if ((fd0 = open(filename0, O_CREAT|O_TRUNC|O_WRONLY, 0644)) < 0) { // work/file_1_1.xml_stringreplace.zip
		output("error opening %s: %m\n", filename0);
		goto out;
	}
	if ((fd1 = open(filename1, O_RDONLY)) < 0) { // file_1_1.xml
		printf("error opening %s: %m\n", filename1);
		goto out;
	}

	count = read(fd1, buf, sizeof(buf));
//	Data (1290 bytes)

	write(fd0, buf, 816);
//	Data (816 bytes)

	if ((fd2 = open(filename2, O_CREAT|O_TRUNC|O_RDWR, 0644)) < 0) { // "work/file_1_1.xml__temp"
		printf("error opening %s: %m\n", filename2);
		goto out;
	}
	write(fd2, buf, 1290);

	if (stat(filename3, &st1) == 0 || errno != ENOENT) {
		if (errno != ENOENT)
			printf("file '%s' should not have existed: %m\n", filename3);
		else
			printf("file '%s' should not have existed\n", filename3);
		goto out;
	}
				; // "work/file_1_1.xml"
	if (stat(filename3, &st1) == 0 || errno != ENOENT) { // "work/file_1_1.xml"
		if (errno != ENOENT)
			printf("file '%s' should not have existed: %m\n", filename3);
		else
			printf("file '%s' should not have existed\n", filename3);
		goto out;
	}

	close_fd(fd2);

	stat(filename2, &st1);
	if (rename(filename2, filename3) < 0) { // "work/file_1_1.xml__temp", "work/file_1_1.xml"
		printf("error renaming %s -> %s: %m\n", filename2, filename3);
		goto out;
	}
	stat(filename3, &st2);
	if ((intmax_t)st1.st_size != (intmax_t)st2.st_size) {
		printf("file size prior to rename: %ld, file size after rename: %ld\n", (intmax_t)st1.st_size, (intmax_t)st2.st_size);
		goto out;
	}
	close_fd(fd1);

	if (unlink(filename1) < 0) { // file_1_1.xml
		printf("error removing %s: %m\n", filename1);
		goto out;
	}
	close_fd(fd0);

//	dfd0 = open("work", O_DIRECTORY);
//	getdents(dfd0, buf, 65536);
//	close_fd(dfd0);
//	dfd0 = open("work", O_DIRECTORY);
//	getdents(dfd0, buf, 65536);

	if ((fd0 = open(filename4, O_CREAT|O_TRUNC|O_RDWR, 0644)) < 0) { // "work/file_1_1.xml_checkxsltmerge.zip"
		printf("error opening %s: %m\n", filename4);
		goto out;
	}
	if ((fd1 = open(filename3, O_RDONLY)) < 0) { // "work/file_1_1.xml"
		printf("error opening %s: %m\n", filename3);
		goto out;
	}
	read(fd1, buf, sizeof(buf));
//	Data (1290 bytes)
	write(fd0, buf, 816);
//	Data (816 bytes)

	if (stat(filename5, &st1) == 0 || errno != ENOENT) { // "work/file_1_1.xml.tmp"
		if (errno != ENOENT)
			printf("file '%s' should not have existed: %m\n", filename5);
		else
			printf("file '%s' should not have existed\n", filename5);
		goto out;
	}

	if ((fd2 = open(filename5, O_CREAT|O_EXCL|O_RDWR, 0644)) < 0) { // "work/file_1_1.xml.tmp"
		printf("error opening %s: %m\n", filename5);
		goto out;
	}
	fsync(fd2);
	ftruncate(fd2, 0);

	if ((fd3 = open(filename5, O_CREAT|O_TRUNC|O_RDWR, 0644)) < 0) { // "work/file_1_1.xml.tmp"
		printf("error opening %s: %m\n", filename5);
		goto out;
	}
	write(fd2, buf, 1256);


	close_fd(fd3);
	close_fd(fd2);
	close_fd(fd1);

	stat(filename5, &st1);
	if (rename(filename5, filename3) < 0) { // "work/file_1_1.xml.tmp", "work/file_1_1.xml"
		printf("error renaming %s -> %s: %m\n", filename5, filename3);
		goto out;
	}
	stat(filename3, &st2);

	if ((intmax_t)st1.st_size != (intmax_t)st2.st_size) {
		printf("file size prior to rename: %ld, file size after rename: %ld\n", (intmax_t)st1.st_size, (intmax_t)st2.st_size);
		goto out;
	}
	if ((fd1 = open(filename3, O_RDONLY)) < 0) { //"work/file_1_1.xml"
		printf("error opening %s: %m\n", filename3);
		goto out;
	}
	read(fd1, buf, sizeof(buf)); // 1256

	close_fd(fd0);
	close_fd(fd1);

	if (unlink(filename3) < 0) {// "work/file_1_1.xml"
		printf("error removing %s: %m\n", filename3);
		goto out;
	}

	ret = EXIT_SUCCESS;
out:
	close_fd(fd0);
	close_fd(fd1);
	close_fd(fd2);
	close_fd(fd3);
	free_buf(filename0); // work/file_1_1.xml_stringreplace.zip
	free_buf(filename1); // file_1_1.xml
	free_buf(filename2); // work/file_1_1.xml__temp
	free_buf(filename3); // work/file_1_1.xml
	free_buf(filename4); // work/file_1_1.xml_checkxsltmerge.zip
	free_buf(filename5); // work/file_1_1.xml.tmp

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
	int filenum;

	if (argc == 4) {
		filenum = strtol(argv[2], NULL, 10);
		num_threads = strtol(argv[3], NULL, 10);
	} else if (argc == 3) {
		filenum = strtol(argv[2], NULL, 10);
	} else if (argc == 2) {
		filenum = strtol(argv[1], NULL, 10);
	} else {
		output("Usage: %s <test_path> [<filenum> [<num_threads>]]\n", argv[0]);
		return EXIT_FAILURE;
	}

	threads = malloc(num_threads * sizeof(pthread_t));
	thread_data = malloc(num_threads * sizeof(thread_data_t));
	for (int i = 0; i < num_threads ; i++) {
		thread_data[i].threadnum = i;
		thread_data[i].filenum = filenum;
		thread_data[i].result = EXIT_FAILURE;

		if (pthread_create(&threads[i], NULL, thread_wrapper, &thread_data[i]) != 0) {
			output("Error creating thread %d\n", i);
			return EXIT_FAILURE;
		}
	}

	// Reap all threads
	for (int i = 0; i < num_threads ; i++) {
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
