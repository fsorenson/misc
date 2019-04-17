#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>

#define DEBUG 0
#define READ_SIZE (256L * 1024L)

#define mb()	__asm__ __volatile__("mfence" ::: "memory")
#define nop()	__asm__ __volatile__ ("nop")

pid_t gettid(void) {
	return syscall(SYS_gettid);
}

typedef enum {
	test_unconf = 0,
	test_child_ready,
	test_begin,
	test_io_stop,
} __attribute__((packed)) test_state;

struct config_struct {
	volatile test_state state;

	int fd;
	char *file_name;
//	unsigned long long block_num;

	unsigned long pid;
	unsigned long child_tid;
} config;

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)
#define debug_output(args...) do { \
	if (DEBUG) \
		output(args); \
} while (0)

#define exit_fail(args...) do { \
	output(args); exit(EXIT_FAILURE); } while (0)

#define error_exit_fail(args...) do { \
	output("Error %d: %s - ", errno, strerror(errno)); \
	exit_fail(args); \
	} while (0)

void *work_thread(void *arg) {
	char *buf;
	ssize_t ret;

	config.child_tid = gettid();
	debug_output("child thread %lu starting up\n", config.child_tid);

	buf = calloc(READ_SIZE, sizeof(char));

	config.state = test_child_ready;
	mb();

	while (config.state != test_begin)
		nop();

	if ((ret = pread(config.fd, buf, READ_SIZE, 0)) != READ_SIZE)
		error_exit_fail("tried to read %ld, but only got %lld\n",
			READ_SIZE, (long long int)ret);

	debug_output("worker thread completed read\n");
	config.state = test_io_stop;
	mb();

	free(buf);
	close(config.fd);
	pthread_exit(NULL);
}

void do_test(void) {
	pthread_attr_t attr;
	pthread_t tid;

	config.pid = getpid();
	debug_output("Main thread (%lu) beginning test\n", config.pid);

	pthread_attr_init(&attr);
	pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setstacksize(&attr, (size_t) (1 * 1024 * 1024));

	if (pthread_create(&tid, &attr, work_thread, (void *) NULL) != 0)
		error_exit_fail("pthread_create()\n");

	while (config.state != test_child_ready)
		nop();

	config.state = test_begin;
	mb();

	while (config.state != test_io_stop)
		nop();

	pthread_kill(tid, SIGKILL);
	// we should never get here, since pthread_kill(SIGKILL) should kill all threads

	close(config.fd);
}

void do_setup(void) {
	struct stat st;
	struct flock fl;

	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 1;

	config.state = test_unconf;

	if (stat(config.file_name, &st))
		error_exit_fail("Error during stat(%s)\n", config.file_name);
	if (st.st_size < READ_SIZE)
		exit_fail("file size (%ld) is smaller than the read size (%ld)\n",
			st.st_size, READ_SIZE);

	debug_output("Setting up test with read size of %ld KiB and file size %ld KiB\n",
		READ_SIZE / 1024, st.st_size / 1024);

	if ((config.fd = open(config.file_name, O_RDONLY, S_IRUSR | S_IWUSR)) < 0)
		error_exit_fail("Error opening file %s: %s\n", config.file_name, strerror(errno));

	if (fcntl(config.fd, F_SETLK, &fl) != 0)
		error_exit_fail("fcntl(F_SETLK) failed while setting lock on %s: %s\n",
			config.file_name, strerror(errno));
}

int main(int argc, char *argv[]) {

	if (argc != 2)
		exit_fail("Usage: %s <test_file>\n", argv[0]);

	config.file_name = argv[1];

	output("Beginning test\n");
	do_setup();
	fflush(stdout);
	do_test();

	output("Test completed?\n");

	exit_fail("We should have exited on a SIGKILL\n");
}
