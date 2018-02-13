/*
	Frank Sorenson <sorenson@redhat.com>, 2017

	Multiple threads repeatedly:
		select one of the given paths at random
		select a random gid within the given range
		setregid() to the selected gid
		open() the file

	usage:  open_paths_as_gids <threads> <start_gid> <end_gid> <path> [<path> ...]
		start_gid and end_gid should be numeric, and are inclusive
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>

#define RAND_STATE_SIZE 256

struct shared_info_struct {
	char **paths;
	int path_count;

	pid_t *cpids;
	gid_t start_gid;
	gid_t end_gid;
	int thread_count;
	int permission_denied;

        struct random_data random_data;
        char random_statebuf[RAND_STATE_SIZE];
};
struct shared_info_struct *shared_info;

int pickanum(int _low, int _high) { /* both inclusive */
        int low, high;
        int spread;
        int r;

        if (_low < _high) { low = _low ; high = _high; }
        else { low = _high; high = _low; }

        spread = high - low;
        random_r(&shared_info->random_data, &r);
        return (r % (spread + 1)) + low;
}

int do_work(int thread_id) {
	gid_t rand_gid;
	int rand_file;
	int fd;

	while (1) {
		rand_file = pickanum(0, shared_info->path_count - 1);
		rand_gid = pickanum(shared_info->start_gid, shared_info->end_gid);

		setregid(-1, rand_gid);
		if ((fd = open(shared_info->paths[rand_file], O_RDWR)) < 0) {
			printf("thread %d with gid %d got '%m' when opening %s\n",
				thread_id, rand_gid, shared_info->paths[rand_file]);
			fflush(stdout);
			shared_info->permission_denied++;
			return EXIT_FAILURE;
		}
		close(fd);
		if (shared_info->permission_denied) {
			printf("thread %d exiting on other thread error\n", thread_id);
			fflush(stdout);
			return EXIT_SUCCESS;
		}
	}
}

int main(int argc, char *argv[]) {
	pid_t cpid;
	int i;

	if (argc < 5) {
		printf("usage: %s <threads> <start_gid> <end_gid> <path> [<path>] [<path>]\n", argv[0]);
		return EXIT_FAILURE;
	}

	shared_info = mmap(NULL, sizeof(struct shared_info_struct), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	shared_info->thread_count = strtol(argv[1], NULL, 10);
	shared_info->start_gid = strtol(argv[2], NULL, 10);
	shared_info->end_gid = strtol(argv[3], NULL, 10);

	if (shared_info->end_gid - shared_info->start_gid + 1 <= 0) {
		printf("invalid start/end gid: %d - %d\n", shared_info->start_gid, shared_info->end_gid);
		return EXIT_FAILURE;
	}

	shared_info->path_count = argc - 4;
	shared_info->paths = malloc(shared_info->path_count * sizeof(char *));
	for (i = 0 ; i < shared_info->path_count ; i++)
		shared_info->paths[i] = argv[i + 4];

        initstate_r((time(NULL) % INT_MAX), shared_info->random_statebuf,
                RAND_STATE_SIZE, &shared_info->random_data);

	printf("starting %d threads to call stat on %d paths with gids %u through %u\n",
		shared_info->thread_count, shared_info->path_count, shared_info->start_gid, shared_info->end_gid);

	for (i = 0 ; i < shared_info->thread_count ; i++) {
		if ((cpid = fork()) == 0) {
			return do_work(i);
		}
	}

	while (! shared_info->permission_denied)
		sleep(1);

	return EXIT_SUCCESS;
}
