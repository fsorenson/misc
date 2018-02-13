#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>

#define NUM_FILES 10
#define TIMING_LOOPS (100000ULL)

#define TEST_NUM 1

static int num_child_threads;
static pid_t *child_pids;

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

/* frees cwd */
char **make_filenames(char *cwd, int child_id) {
	char **filenames;
	int i;

	filenames = malloc(NUM_FILES * sizeof(char *));
	for (i=0 ; i < NUM_FILES ; i++)
		asprintf(&filenames[i], "%s/file%d.%d", cwd, child_id, i);
	free(cwd);

	return filenames;
}

struct timespec ts_elapsed(const struct timespec ts1, const struct timespec ts2) {
	struct timespec ret, a, b;
	if ((ts1.tv_sec > ts2.tv_sec) ||
		((ts1.tv_sec == ts2.tv_sec) && (ts1.tv_nsec >= ts2.tv_nsec))) {
		a = ts1; b = ts2;
	} else {
		a = ts2; b = ts1;
	}
	ret.tv_sec = a.tv_sec - b.tv_sec - 1;
	ret.tv_nsec = a.tv_nsec - b.tv_nsec + 1000000000;
	while (ret.tv_nsec >= 1000000000) {
		ret.tv_sec ++;
		ret.tv_nsec -= 1000000000;
	}
	return ret;
}


/* parent process gathers some timing information */
void do_stat_times(char *cwd) {
	struct timespec start_ts, end_ts;
	struct timespec elapsed, ts;
	unsigned long elapsed_ns;
	char **filenames;
	struct stat st;
	int i, j;

	filenames = make_filenames(cwd, NUM_FILES);
	ts.tv_sec = 2; ts.tv_nsec = 0;
	nanosleep(&ts, NULL);

	printf("starting timing loops\n");
	printf("%d child threads, %llu loops, %d files: ", num_child_threads, TIMING_LOOPS, NUM_FILES);
	fflush(stdout);
//	while (1) {
		clock_gettime(CLOCK_REALTIME, &start_ts);
		for (i = 0 ; i < TIMING_LOOPS ; i++) {
			for (j = 0 ; j < NUM_FILES ; j++)
				stat(filenames[j], &st);
		}
		clock_gettime(CLOCK_REALTIME, &end_ts);
		elapsed = ts_elapsed(start_ts, end_ts);

		elapsed_ns = elapsed.tv_sec * 1000000000 + elapsed.tv_nsec;
		printf("stat: %llu ns/call/thread", elapsed_ns / TIMING_LOOPS / NUM_FILES / num_child_threads);
		fflush(stdout);


		clock_gettime(CLOCK_REALTIME, &start_ts);
		for (i = 0 ; i < TIMING_LOOPS ; i++) {
			for (j = 0 ; j < NUM_FILES ; j++)
				access(filenames[j], F_OK);
		}
		clock_gettime(CLOCK_REALTIME, &end_ts);
		elapsed = ts_elapsed(start_ts, end_ts);

		elapsed_ns = elapsed.tv_sec * 1000000000 + elapsed.tv_nsec;
		printf(", access: %llu ns/call/thread", elapsed_ns / TIMING_LOOPS / NUM_FILES / num_child_threads);
		printf("\n");
		fflush(stdout);
//	}
	kill(-getpid(), SIGINT);
}

void do_file_stats(char *cwd, int child_id) {
	char **filenames;
	struct stat st;
	char *f;
	int i;

	filenames = make_filenames(cwd, child_id);
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
        int child_id;
	pid_t cpid;
	char *cwd;

	if (argc != 2) {
		printf("Usage: %s <number_of_child_tasks>\n", argv[0]);
		return EXIT_FAILURE;
	}
	if ((num_child_threads = strtol(argv[1], NULL, 10)) < 1) {
		printf("unable to parse number of child tasks: '%s'\n", argv[1]);
		return EXIT_FAILURE;
	}

	setpgid(0, getpid());

	cwd = get_current_dir_name();
	printf("starting %d processes\n", num_child_threads);
	for (child_id = 0 ; child_id < num_child_threads ; child_id++)
		if ((cpid = fork()) == 0)
			do_file_stats(cwd, child_id);
#if TEST_NUM == 1
	do_stat_times(cwd);

	return EXIT_SUCCESS;
#elif TEST_NUM == 2
	free(cwd);
	do_drop_caches();

	return EXIT_FAILURE;
#else
	/* something else... */
	while (1) {
		pause();
	}
	return EXIT_FAILURE;
#endif

}
