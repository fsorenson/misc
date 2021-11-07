#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)

#define BLOCK_SIZE (8 * KiB)


#define MAX_FILES 100
#define MIN_FILES 10

#define TESTPATH "/mnt/tmp"


int main(int argc, char *argv[]) {
	int fds[MAX_FILES];
	char *filenames[MAX_FILES];
	size_t current_sizes[MAX_FILES];
	int current_files, current_file;
	int i;


	for (current_files = 0 ; current_files < MAX_FILES ; current_files++) {
		asprintf(&filenames[current_files], "%s/testfile_%d", TESTPATH, current_files);
		if ((fds[current_files] = open(filenames[current_files], O_CREAT|O_RDWR, 0666)) < 0) {
			printf("failed to open '%s': %m\n", filenames[current_files]);
			return EXIT_FAILURE;
		}
		current_sizes[current_files] = lseek(fds[current_files], 0, SEEK_END);
	}

	while (42) {
		printf("writing %d files      \r", current_files);
		fflush(stdout);

		current_file = 0;
		while (42) {
			if (fallocate(fds[current_file], 0, current_sizes[current_file], BLOCK_SIZE) < 0)
				break;
			if (ftruncate(fds[current_file], current_sizes[current_file] + (2 * BLOCK_SIZE)) < 0)
				break;

			current_sizes[current_file] += (2 * BLOCK_SIZE);

			current_file++;
			if (current_file == current_files) {
				current_file = 0;
			}
		}
		if (current_files <= MIN_FILES)
			break;

		close(fds[current_files - 1]);
		unlink(filenames[current_files - 1]);
		free(filenames[current_files - 1]);
		current_files--;
	}

	while (current_files > 0) {
		close(fds[current_files - 1]);
		free(filenames[current_files - 1]);
		current_files--;
	}



	return EXIT_SUCCESS;
}
