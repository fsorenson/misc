#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>
#include <sched.h>
#include <sys/wait.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <numa.h>


#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)
#define TiB (KiB * KiB * KiB * KiB)

#define K (1000ULL)
#define M (K * K)
#define B (K * K * K)


#define CHILD_THREADS 20
#define DEFAULT_PATH "/var/tmp/testdir"
#define NUMA_MOVE_NSEC 100000000

#define MIN_FILE_SIZE (2 * MiB)
#define MAX_FILE_SIZE (6 * MiB)

#define MIN_WRITE_SIZE (75)
#define MAX_WRITE_SIZE (300)

#define RAND_STATE_SIZE 256
#define BUF_SIZE (4096)

struct shared_data_struct {
	struct random_data random_data;
	char *random_statebuf;

	char *test_base_dir;

	pid_t parent_pid;
	pid_t child_pids[CHILD_THREADS];
	struct bitmask *child_current_node[CHILD_THREADS];

} *shared_data;

int state_pickanum(struct random_data *random_data, int _low, int _high) { /* both inclusive */
	int low, high;
	int spread;
	int r;

	if (_low < _high) { low = _low ; high = _high; }
	else { low = _high; high = _low; }

	spread = high - low;
	random_r(random_data, &r);
	return (r % (spread + 1)) + low;
}
int pickanum(int _low, int _high) { /* both inclusive */
	return state_pickanum(&shared_data->random_data, _low, _high);
}
int thread_pickanum(struct random_data *random_data, int _low, int _high) {
	return state_pickanum(random_data, _low, _high);
}
int child_work(int myid) {
	unsigned long chosen_file_size;
	int write_size;
	char *testfile;
	char *buf;
	int fd;

	struct random_data thread_random_data;
	char *thread_random_statebuf;

	memset(&thread_random_data, 0, sizeof(struct random_data));
	thread_random_statebuf = malloc(RAND_STATE_SIZE);
	memset(thread_random_statebuf, 0, RAND_STATE_SIZE);

	initstate_r(pickanum(0, INT_MAX), thread_random_statebuf, RAND_STATE_SIZE, &thread_random_data);

	asprintf(&testfile, "%s/%d", shared_data->test_base_dir, myid);
	buf = malloc(BUF_SIZE);
	memset(buf, 0x55, BUF_SIZE);

	while (42) {
		unsigned long pos = 0;
		chosen_file_size = thread_pickanum(&thread_random_data, MIN_FILE_SIZE, MAX_FILE_SIZE);

		if ((fd = open(testfile, O_RDWR|O_CREAT|O_TRUNC, 0664)) < 0) {
			printf("failed to open '%s': %m\n", testfile);
			goto out;
		}

		fallocate(fd, 0, 0, chosen_file_size);
		while (pos < chosen_file_size) {
			write_size = thread_pickanum(&thread_random_data, MIN_WRITE_SIZE, MAX_WRITE_SIZE);
			write_size = BUF_SIZE;
			write(fd, buf, write_size);
			pos += write_size;
		}
		close(fd);
	}
out:
	return EXIT_FAILURE;
}


int main(int argc, char *argv[]) {
	char *err_string = "%s: numa error occurred while '%s': %m";
	char *err_action = NULL;
	int num_nodes;
	int max_node;
	struct bitmask **nodes;
	pid_t cpid;
	int ret;
	int i;

	num_nodes = numa_num_configured_nodes();
	if (num_nodes > 1) {
		printf("creating %d child threads; pushing them between %d numa nodes\n", CHILD_THREADS, num_nodes);
		nodes = malloc(sizeof(struct bitmask *) * num_nodes);
		memset(nodes, 0, sizeof(struct bitmask *) * num_nodes);
		for (i = 0 ; i < num_nodes ; i++) {
			nodes[i] = numa_allocate_nodemask();
			numa_bitmask_setbit(nodes[i], i);
		}
		max_node = num_nodes - 1;
	}



//	shared_data = mmap(NULL, sizeof(unsigned long),
	shared_data = mmap(NULL, sizeof(struct shared_data_struct),
		PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	memset(shared_data, 0, sizeof(struct shared_data_struct));

	shared_data->random_statebuf = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE,
		-1, 0);
	memset(shared_data->random_statebuf, 0, RAND_STATE_SIZE);
	initstate_r((time(NULL) % INT_MAX),
		shared_data->random_statebuf, RAND_STATE_SIZE,
		&shared_data->random_data);

	if (argc == 2)
		shared_data->test_base_dir = argv[1];
	else
		shared_data->test_base_dir = DEFAULT_PATH;

	for (i = 0 ; i < CHILD_THREADS ; i++) {
		if (num_nodes > 1)
			shared_data->child_current_node[i] = numa_get_membind();
		if ((cpid = fork()) == 0)
			return child_work(i);
		shared_data->child_pids[i] = cpid;
	}
	while (42) {
		if (num_nodes > 1) {
			struct timespec ts;
			// constantly switch up numa nodes
			int new_node;
			for (i = 0 ; i < CHILD_THREADS ; i++) {
repick_node:
				new_node = pickanum(0, max_node);
				if (shared_data->child_current_node[i] == nodes[new_node])
					goto repick_node;
//flick_node:
				if ((ret = numa_migrate_pages(shared_data->child_pids[i], shared_data->child_current_node[i], nodes[new_node])) < 0) {
					asprintf(&err_action, "migrate_pages pid %d -> node %d", shared_data->child_pids[i], new_node);
					goto out_err;
				}
			}
			ts.tv_sec = 0;
			ts.tv_nsec = NUMA_MOVE_NSEC;
			nanosleep(&ts, NULL);
		} else {
			sleep(1);
		}
	}
	if (num_nodes > 1) {
out_err:
		numa_warn(ret, err_string, argv[0], err_action);
		free(err_action);

		for (i = 0 ; i < num_nodes ; i++)
			numa_free_nodemask(nodes[i]);
		free(nodes);
	}

	return EXIT_SUCCESS;
}
