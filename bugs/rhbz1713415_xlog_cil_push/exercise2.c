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



#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)
#define TiB (KiB * KiB * KiB * KiB)

#define K (1000ULL)
#define M (K * K)
#define B (K * K * K)

#define RAND_STATE_SIZE 256


// perl_node: 337
// c_node: 104
// java: 1085
// timestensubd: 264
// timestend: 75
// multipathd: 21
// gssproxy: 6
// sshd: 11
// kdmwork: 15
// kdmflush: 45
// ksh: 13
/*
   1085  "java"
    5a  "perl_node"
    264  "timestensubd"
    104  "c_node"
     75  "timestend"
     49  "bioset"
     45  "kdmflush"
     21  "multipathd"
     13  "ksh"
     11  "sshd"
      9  "python"
      9  "gmetad"
      7  "nbdisco"
      6  "nsrexecd"
      6  "httpd"
      6  "gssproxy"
      6  "cmclconfd"
      5  "sudo"
      5  "cmcld"
      5  "bash"
      4  "tuned"
      4  "crond"
      3  "ttcserver"
      3  "gmain"
      2  "teamd"
      2  "polkitd"
*/

#define CHILD_THREADS 30
#define MIN_FILE_SIZE (2 * MiB)
#define MAX_FILE_SIZE (6 * MiB)

#define MIN_WRITE_SIZE (75)
#define MAX_WRITE_SIZE (300)

#define BUF_SIZE (4096)


struct shared_data_struct {
	struct random_data random_data;
	char *random_statebuf;

	char *test_base_dir;


	pid_t parent_pid;
	pid_t child_pids[CHILD_THREADS];

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
	unsigned long pos = 0;
	unsigned long chosen_file_size;
	struct timespec ts;
	int write_size;
	char *testfile;
	char *buf;
	int sleep_opt;
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
		chosen_file_size = thread_pickanum(&thread_random_data, MIN_FILE_SIZE, MAX_FILE_SIZE);

		if ((fd = open(testfile, O_RDWR|O_CREAT|O_TRUNC, 0664)) < 0) {
			printf("failed to open '%s': %m\n", testfile);
			goto out;
		}
		pos = 0;

		fallocate(fd, 0, 0, chosen_file_size);

		while (pos < chosen_file_size) {
//			write_size = pickanum(MIN_WRITE_SIZE, MAX_WRITE_SIZE);
//			write_size = thread_pickanum(&thread_random_data, MIN_WRITE_SIZE, MAX_WRITE_SIZE);
//			write_size = 1;
			write_size = BUF_SIZE;
			write(fd, buf, write_size);
			pos += write_size;

#if 0
//			sleep_opt = pickanum(0, 588);
			sleep_opt = thread_pickanum(&thread_random_data, 0, 588);
			if (sleep_opt >= 588) { // 1 @ 5.0
				ts.tv_sec = 5; ts.tv_nsec = 0;
			} else if (sleep_opt >= 587) { // 1 @ 60.0
				ts.tv_sec = 60; ts.tv_nsec = 0;
			} else if (sleep_opt >= 585) { // 2 @ 10.0
				ts.tv_sec = 10; ts.tv_nsec = 0;
			} else if (sleep_opt >= 581) { // 4 @ 0.0 (no sleep)
				ts.tv_sec = 0; ts.tv_nsec = 0;
			} else if (sleep_opt >= 559) { // 22 @ 0.2
				ts.tv_sec = 0; ts.tv_nsec = 200000000;
			} else if (sleep_opt >= 536) { // 23 @ 2.0
				ts.tv_sec = 2; ts.tv_nsec = 0;
			} else if (sleep_opt >= 339) { // 197 @ 1.0
				ts.tv_sec = 1; ts.tv_nsec = 0;
			} else { // 0.1
				ts.tv_sec = 0; ts.tv_nsec = 100000000;
			}
ts.tv_sec = ts.tv_sec / 2;
ts.tv_nsec >>= 2;
			nanosleep(&ts, NULL);

#endif


		}
		close(fd);
	}
out:
	return EXIT_FAILURE;
}


int main(int argc, char *argv[]) {
	pid_t cpid;
	int i;


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

	shared_data->test_base_dir = "/var/tmp/testdir";


	for (i = 0 ; i < CHILD_THREADS ; i++) {
		if ((cpid = fork()) == 0)
			return child_work(i);
		shared_data->child_pids[i] = cpid;
	}
	while (42)
		sleep(1);

	return EXIT_SUCCESS;
}
