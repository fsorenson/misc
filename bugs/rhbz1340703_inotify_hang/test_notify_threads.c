/*
	Frank Sorenson <sorenson@redhat.com>
	Red Hat, 2016

	program to reproduce inotify hang in RHEL 7
	uses monitor thread and 3 worker threads
	expected to reproduce the hang within 5-10 seconds

	usage: test_threads directory_to_monitor directory_to_monitor/filename

	# gcc test_threads.c -o test_threads -l pthread
	# mkdir /tmp/test_dir
	# ./test_threads /tmp/test_dir /tmp/test_dir/test_file
*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>

#include <sys/fanotify.h>

#define THREADS 3
#define NOTIFY_THREADS 2
#define ITER_COUNT 10000
#define PROGRESS_INTERVAL 50 /* don't flood */
#define QUIET 1

#define unlikely(x)     __builtin_expect((x),0)
#define progress_counter(_ctr, _output) do { \
	if (unlikely( ! (--_ctr) )) { \
		printf(_output); \
		fflush(stdout); \
		_ctr = PROGRESS_INTERVAL; \
	} \
} while (0)

pthread_t tid[THREADS];
pthread_t notify_tid[NOTIFY_THREADS];
static char *test_file;
static char *test_dir;

char *monitored_path; // directory path
#define FANOTIFY_BUFFER_SIZE 8192

enum {
	FD_POLL_SIGNAL = 0,
	FD_POLL_FANOTIFY,
	FD_POLL_MAX
};

static uint64_t event_mask = ( FAN_OPEN_PERM | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD | FAN_ONDIR );


#if ! QUIET
static char *get_program_name_from_pid (int pid, char *buffer, size_t buffer_size) {
	int fd;
	ssize_t len;
	char *aux;

	/* Try to get program name by PID */
	sprintf (buffer, "/proc/%d/cmdline", pid);
	if ((fd = open (buffer, O_RDONLY)) < 0)
		return NULL;

	/* Read file contents into buffer */
	if ((len = read (fd, buffer, buffer_size - 1)) <= 0) {
		close (fd);
		return NULL;
	}
	close (fd);

	buffer[len] = '\0';
	aux = strstr (buffer, "^@");
	if (aux)
		*aux = '\0';

	return buffer;
}
static char *get_file_path_from_fd (int fd, char *buffer, size_t buffer_size) {
	ssize_t len;

	if (fd <= 0)
		return NULL;

	sprintf (buffer, "/proc/self/fd/%d", fd);
	if ((len = readlink (buffer, buffer, buffer_size - 1)) < 0)
		return NULL;

	buffer[len] = '\0';
	return buffer;
}
#endif

static void process_event(struct fanotify_event_metadata *event) {
#if QUIET
	static unsigned long long counter = PROGRESS_INTERVAL;
	progress_counter(counter, ".");
#else
	char path[PATH_MAX];

	printf("Received event in fd %d, path '%s'", event->fd,
		get_file_path_from_fd(event->fd, path, PATH_MAX) ? path : "unknown");
	printf("	pid=%d (%s): ", event->pid,
				(get_program_name_from_pid(event->pid,
					path, PATH_MAX) ? path : "unknown"));
	if (event->mask & FAN_CLOSE_WRITE)
		printf("FAN_CLOSE_WRITE ");
	if (event->mask & FAN_OPEN_PERM)
		printf("FAN_OPEN_PERM");
	printf("\n");
	fflush(stdout);
#endif

	close(event->fd);
}
static void shutdown_fanotify(int fanotify_fd) {
	fanotify_mark(fanotify_fd, FAN_MARK_REMOVE, event_mask, AT_FDCWD, monitored_path);
	free(monitored_path);
	close(fanotify_fd);
}

static int init_fanotify(char *path) {
	int fanotify_fd;

	fanotify_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY | O_CLOEXEC | O_LARGEFILE);
	if (fanotify_fd < 0) {
		printf("Error setting up new fanotify device: %m\n");
		return -1;
	}

	monitored_path = strdup(path);
	if (fanotify_mark(fanotify_fd, FAN_MARK_ADD|FAN_MARK_MOUNT,
		event_mask, AT_FDCWD, monitored_path) < 0) {
		printf("Error setting up monitor for directory '%s': %m\n", monitored_path);
		return -1;
	}
	printf("started monitoring directory '%s'\n", monitored_path);

	return fanotify_fd;
}

static void shutdown_sigs(int signal_fd) {
	close(signal_fd);
}
static int init_sigs(void) {
	int signal_fd;
	sigset_t sigmask;

	sigemptyset (&sigmask);
	sigaddset (&sigmask, SIGINT);
	sigaddset (&sigmask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) < 0) {
		printf("Error blocking signals: %m\n");
		return -1;
	}

	if ((signal_fd = signalfd(-1, &sigmask, 0)) < 0) {
		printf("Error setting up signal fd: %m\n");
		return -1;
	}
	return signal_fd;
}


void *work(void *arg) {
	unsigned long i = 0;
	char buf[BUFSIZ];
	int fd;
	int len;
	int myid = (arg - (void *)&tid[0]) / sizeof(tid[0]);

	printf("thread %d is live\n", myid);
	sleep(1);

	while (1) {
		len = snprintf(buf, BUFSIZ, "count: %lu\n", i++);

		fd = open(test_file, O_RDWR | O_CREAT | O_APPEND, 0660);
		write(fd, buf, len);
		close(fd);
		if (i > ITER_COUNT)
			break;
	}
	printf("thread %d exiting\n", myid);
	sleep(1);
	exit(EXIT_SUCCESS);
	return NULL;
}

void *notify_work(void *arg) {
	int signal_fd;
	int fanotify_fd;
	struct pollfd fds[FD_POLL_MAX];
	int myid = (arg - (void *)&notify_tid[0]) / sizeof(notify_tid[0]);

	printf("notify thread %d is live\n", myid);

	if ((signal_fd = init_sigs()) < 0) {
		printf("Error initializing signals\n");
		exit(EXIT_FAILURE);
	}
	if ((fanotify_fd = init_fanotify(test_dir)) < 0) {
		printf("Error initializing fanotify\n");
		exit(EXIT_FAILURE);
	}
	fds[FD_POLL_SIGNAL].fd = signal_fd;
	fds[FD_POLL_SIGNAL].events = POLLIN;
	fds[FD_POLL_FANOTIFY].fd = fanotify_fd;
	fds[FD_POLL_FANOTIFY].events = POLLIN;

	while (1) {
		if (poll(fds, FD_POLL_MAX, -1) < 0) {
			printf("Error with poll(): %m\n");
			exit(EXIT_FAILURE);
		}
		if (fds[FD_POLL_SIGNAL].revents & POLLIN) {
			struct signalfd_siginfo fdsi;

			if (read(fds[FD_POLL_SIGNAL].fd, &fdsi, sizeof (fdsi)) != sizeof (fdsi)) {
				printf("Error reading signal, wrong size read\n");
				exit(EXIT_FAILURE);
			}


			/* Break loop if we got the expected signal */
			if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM)
				break;
			printf("Received unexpected signal\n");
		}
		if (fds[FD_POLL_FANOTIFY].revents & POLLIN) {
			char buffer[FANOTIFY_BUFFER_SIZE];
			ssize_t length;

			/* Read from the FD. It will read all events available up to
			* the given buffer size. */
			if ((length = read (fds[FD_POLL_FANOTIFY].fd, buffer, FANOTIFY_BUFFER_SIZE)) > 0) {
				struct fanotify_event_metadata *metadata;

				metadata = (struct fanotify_event_metadata *)buffer;
				while (FAN_EVENT_OK(metadata, length)) {
					process_event(metadata);
					struct fanotify_response * resp = malloc(sizeof(struct fanotify_response));
					resp->fd=metadata->fd;
					resp->response= FAN_ALLOW;
					write(fds[FD_POLL_FANOTIFY].fd, resp, sizeof(struct fanotify_response));
					free((void*)resp);
					metadata = FAN_EVENT_NEXT(metadata, length);
				}
			}
		}
	}

	shutdown_fanotify(fanotify_fd);
	shutdown_sigs(signal_fd);

	printf("exiting monitor on signal\n");
	exit(EXIT_FAILURE);
}


int main(int argc, char *argv[]) {
	int i;
	int ret;

	if (argc != 3) {
		printf("Usage: %s <test_directory> <test_file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	test_dir = argv[1];
	test_file = argv[2];

	for (i = 0 ; i < THREADS ; i++) {
		ret = pthread_create(&(tid[i]), NULL, &work, &(tid[i]));
		if (ret != 0) {
			printf("\nthread creation failed: %m\n");
			return EXIT_FAILURE;
		}
	}

	for (i = 0 ; i < NOTIFY_THREADS ; i++) {
		ret = pthread_create(&(notify_tid[i]), NULL, &notify_work, &(notify_tid[i]));
		if (ret != 0) {
			printf("\nnotify thread creation failed: %m\n");
			return EXIT_FAILURE;
		}
	}

	pause();

	kill(0, SIGKILL);

	printf("cleaning up for exit\n");
	for (i = 0 ; i < THREADS ; i++)
		pthread_join(tid[i], NULL);
	sleep(2);
	for (i = 0 ; i < NOTIFY_THREADS ; i++)
		pthread_join(notify_tid[i], NULL);
	printf("monitor exiting\n");
	return EXIT_SUCCESS;
}
