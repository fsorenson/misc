#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define NUM_FILES 10

void do_drop_caches(void) {
	struct timespec ts;
	int fd;

	ts.tv_sec = 60;
	ts.tv_nsec = 0;
	printf("started child processes.  sleeping %ld seconds...\n", ts.tv_sec);
	nanosleep(&ts, NULL);

	printf("attempting to hang system by dropping caches\n");
	if ((fd = open("/proc/sys/vm/drop_caches", O_RDWR)) < 0)
		printf("Error opening drop_caches sysctl: %m\n");
	else {
		write(fd, "3\n", 2);
		close(fd);
		printf("WARNING: test program failed to fail: expected system hang did not occur\n");
	}
}

void do_file_stats(char *cwd, int child_id) {
	char **filenames;
	struct stat st;
	char *f;
	int i;

	filenames = malloc(NUM_FILES * sizeof(char *));
	for (i=0 ; i < NUM_FILES ; i++)
		asprintf(&filenames[i], "%s/file%d.%d", cwd, child_id, i);
	free(cwd);

	close(fileno(stdin));
	close(fileno(stdout));
	close(fileno(stderr));

	while (1) {
		for (i = 0 ; i < NUM_FILES ; i++) {
			f = filenames[i];
			stat(f, &st);
			access(f, F_OK);
			stat(f, &st);
		}
	}
}

int main(int argc, char *argv[]) {
	int child_tasks;
        int child_id;
	pid_t cpid;
	char *cwd;

	if (argc != 2) {
		printf("Usage: %s <number_of_child_tasks>\n", argv[0]);
		return EXIT_FAILURE;
	}
	if ((child_tasks = strtol(argv[1], NULL, 10)) < 1) {
		printf("unable to parse number of child tasks: '%s'\n", argv[1]);
		return EXIT_FAILURE;
	}

	cwd = get_current_dir_name();
	printf("starting %d processes\n", child_tasks);
	for (child_id = 0 ; child_id < child_tasks ; child_id++)
		if ((cpid = fork()) == 0)
			do_file_stats(cwd, child_id);
	free(cwd);
	do_drop_caches();

	return EXIT_FAILURE;
}
