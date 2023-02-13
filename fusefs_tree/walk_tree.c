#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#define KiB                     (1024UL)
#define MiB                     (KiB * KiB)
#define GiB                     (KiB * KiB * KiB)

#define USEC_TO_NSEC(v)         (v * 1000UL)
#define MSEC_TO_NSEC(v)         (v * 1000000UL)
#define NSEC                    (1000000000UL)

#define GETDENTS_BUF_SIZE (64UL * KiB)
#define DEFAULT_CHILD_THREADS	(8)

pid_t gettid(void) {
	return syscall(SYS_gettid);
}

pid_t tid;
int child_id = -1;
int child_count = DEFAULT_CHILD_THREADS;
pid_t *cpids;
int children_exited = 0;

#define output2(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define output(fmt, ...) do { \
	output2("tid %d, child %d: " fmt, tid, child_id, ##__VA_ARGS__); \
} while (0)

#define free_mem(var) do { \
	if (var) \
		free(var); \
	var = NULL; \
} while (0)

struct timespec ts_add(const struct timespec ts1, const struct timespec ts2) {
        struct timespec ret = { .tv_sec = ts1.tv_sec + ts2.tv_sec, .tv_nsec = ts1.tv_nsec + ts2.tv_nsec };
        while (ret.tv_nsec >= NSEC) {
                ret.tv_sec++;
                ret.tv_nsec -= NSEC;
        }
        return ret;
}

#define USE_BARRIER 0

#if USE_BARRIER
#define PTHREAD_TBARRIER_CANCELED       (-2)
#define PTHREAD_TBARRIER_DEFAULT_TIMEOUT        (struct timespec){ .tv_sec = 0, .tv_nsec = MSEC_TO_NSEC(1) }
typedef bool (*tbarrier_csncel_func_t)(void);
/* a cancelable barrier */
struct pthread_tbarrier {
        pthread_cond_t cond;
        pthread_mutex_t lock;
        struct timespec timeout; // how long to wait between calls to ->cancel function to check whether to break out

        uint32_t target_count;
        uint32_t threads_left; // alternatively, current_wait_count
        uint32_t cycle;
        bool initialized;
        tbarrier_csncel_func_t cancel; // function to call to check whether to break out of the barrier wait
};
typedef struct pthread_tbarrier pthread_tbarrier_t;

pthread_tbarrier_t *tbar = NULL;

int pthread_tbarrier_init(pthread_tbarrier_t *tbar,
                const pthread_barrierattr_t *restrict attr,
                int target_count, tbarrier_csncel_func_t cancel,
                struct timespec *timeout) {

        int ret = 0;

        memset(tbar, 0, sizeof(pthread_tbarrier_t));
        pthread_mutex_init(&tbar->lock, NULL);
        pthread_mutex_lock(&tbar->lock);
        pthread_cond_init(&tbar->cond, NULL);

        tbar->target_count = target_count;
        tbar->threads_left = target_count;
        tbar->cycle = 0;

        if (timeout) /* pass timeout = NULL to use default of 1.0 seconds */
                tbar->timeout = *timeout;
        else
                tbar->timeout = PTHREAD_TBARRIER_DEFAULT_TIMEOUT;

        tbar->cancel = cancel;
        tbar->initialized = true;

        pthread_mutex_unlock(&tbar->lock);
        return ret;
}
int pthread_tbarrier_destroy(pthread_tbarrier_t *tbar) {
        int ret = EINVAL;

        if (!tbar->initialized)
                goto out;

        pthread_mutex_lock(&tbar->lock);
        pthread_cond_destroy(&tbar->cond);
        tbar->initialized = false;
        pthread_mutex_destroy(&tbar->lock);
        memset(tbar, 0, sizeof(*tbar));

        ret = EXIT_SUCCESS;
out:    
        return ret;
}
int pthread_tbarrier_wait(pthread_tbarrier_t *tbar) {
        uint32_t left, ret = 0;

        pthread_mutex_lock(&tbar->lock);

        if ((left = --tbar->threads_left) == 0) {

                tbar->threads_left = tbar->target_count;
                tbar->cycle++;

                pthread_cond_broadcast(&tbar->cond);

                ret = PTHREAD_BARRIER_SERIAL_THREAD;
                goto out;
        } else {
                uint32_t cycle = tbar->cycle;

                while (cycle == tbar->cycle) {
                        struct timespec wait_stop_time;
                        clock_gettime(CLOCK_REALTIME, &wait_stop_time);

                        wait_stop_time = ts_add(wait_stop_time, tbar->timeout);

                        if (tbar->cancel && tbar->cancel()) {
                                ret = PTHREAD_TBARRIER_CANCELED;
                                break;
                        }

                        if ((ret = pthread_cond_timedwait(&tbar->cond, &tbar->lock, &wait_stop_time)) == 0)
                                break; /* done waiting--we may continue */

                        if (ret == ETIMEDOUT)
                                continue; /* wait timed out... waiting again */

                        output("%d pthread_cond_timedwait returned error: %s\n", getpid(), strerror(ret));
                }

                ret = 0;
                goto out;
        }
out:
        pthread_mutex_unlock(&tbar->lock);
        return ret;

}
uint32_t pthread_tbarrier_get_waiters(pthread_tbarrier_t *tbar) {
        uint32_t waiters;
        pthread_mutex_lock(&tbar->lock);
        waiters = tbar->target_count - tbar->threads_left;
        pthread_mutex_unlock(&tbar->lock);
        return waiters;
}
uint32_t pthread_tbarrier_get_cycle(pthread_tbarrier_t *tbar) {
        uint32_t cycle;
        pthread_mutex_lock(&tbar->lock);
        cycle = tbar->cycle;
        pthread_mutex_unlock(&tbar->lock);
        return cycle;
}
bool pthread_tbarrier_get_cancel(pthread_tbarrier_t *tbar) {
        bool cancel;
        pthread_mutex_lock(&tbar->lock);
        cancel = tbar->cancel;
        pthread_mutex_unlock(&tbar->lock);
        return cancel;
}
#endif /* USE_BARRIER */




struct linux_dirent64 {
	ino64_t		d_ino;		// 64-bit inode number
	off64_t		d_off;		// 64-bit offset to next structure
	unsigned short	d_reclen;	// Size of this dirent
	unsigned char	d_type;		// File type
	char		d_name[];	// Filename (null-terminated)
};

int walk_path(int _dfd, const char *path) {
	struct linux_dirent64 *de;
	char *getdents_buf = NULL, *bpos;
	int ret = EXIT_SUCCESS, nread, dfd = -1;
	struct stat st;

	if (!(getdents_buf = malloc(GETDENTS_BUF_SIZE))) {
		output("error allocating memory: %m\n");
		ret = EXIT_FAILURE;
		goto out;
	}

#if USE_BARRIER
	pthread_tbarrier_wait(tbar);
#endif

	if (_dfd == AT_FDCWD) {
		if ((dfd = open(path, O_RDONLY|O_DIRECTORY)) < 0) {
			output("error opening directory '%s': %m\n", path);
			ret = EXIT_FAILURE;
			goto out;
		}
	} else {
		if ((dfd = dup(_dfd)) < 0) {
			output("error duplicating fd %d for '%s': %m\n", _dfd, path);
			ret = EXIT_FAILURE;
			sleep(120);
			goto out;
		}
	}


	while (42) {
		if ((nread = syscall(SYS_getdents64, dfd, getdents_buf, GETDENTS_BUF_SIZE)) < 0) {
			fstatat(dfd, "", &st, AT_EMPTY_PATH);
			output("error getting directory entries in '%s', inode # %lu: %m\n", path, st.st_ino);
			ret = EXIT_FAILURE;
			goto out;
		}
		if (nread == 0)
			break;

		bpos = getdents_buf;
		while (bpos < getdents_buf + nread) {

			de = (struct linux_dirent64 *)bpos;
			bpos += de->d_reclen;

			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;
			if (de->d_type != DT_DIR)
				continue;

			int next_dfd;
			char *next_path;
			asprintf(&next_path, "%s/%s", path, de->d_name); // FIXME
			if ((next_dfd = openat(dfd, de->d_name, O_RDONLY|O_DIRECTORY)) < 0) {
				output("error opening directory '%s': %m\n", next_path);
				ret = EXIT_FAILURE;
				free_mem(next_path);
				goto out;
			}
			ret = walk_path(next_dfd, next_path);
			close(next_dfd);
			free_mem(next_path);
			if (ret != EXIT_SUCCESS)
				goto out;
		}
	}
out:
	if (dfd != AT_FDCWD)
		close(dfd);
	free_mem(getdents_buf);
	return ret == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

int child_work(int id, const char *path) {
	int ret;

	tid = gettid();
	child_id = id;
	output("alive\n");
	free_mem(cpids);

	ret = walk_path(AT_FDCWD, path);

	output("exiting with %sERROR\n", ret == EXIT_SUCCESS ? "NO " : "");
	usleep(1000);
	return ret;
}

int usage(const char *exe, int ret) {
	output("usage: %s <child_threads> <starting path>\n", exe);
	return ret;
}

void handle_child_exit(int sig, siginfo_t *info, void *ucontext) {
	pid_t pid;
	int status, i;

	while ((pid = wait4(-1, &status, WNOHANG, NULL)) != -1) {
		bool found = false;
		if (pid == 0)
			return;
		for (i = 0 ; i < child_count ; i++) {
			if (cpids[i] == pid) {
				output("child %d exited\n", i);
				cpids[i] = 0;
				found = true;
				children_exited++;
			}
		}
		if (!found)
			output("couldn't find matching child pid: %d (cue Billy Jean)\n", pid);
	}
}

int main(int argc, char *argv[]) {
	int cpid, ret = EXIT_FAILURE, i;
	const char *path;
	sigset_t signal_mask;
	struct sigaction sa;

	if (argc != 3)
		return usage(argv[0], EXIT_FAILURE);

	child_count = strtol(argv[1], NULL, 10);
	if (child_count < 1 || child_count > 1000) {
		output("invalid child count: %d\n", child_count);
		return usage(argv[0], EXIT_FAILURE);
	}
	cpids = malloc(sizeof(pid_t) * child_count);
	memset(cpids, 0, sizeof(pid_t) * child_count);
	path = argv[2];


#if USE_BARRIER
	if ((tbar = mmap(NULL, sizeof(pthread_tbarrier_t), PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
		output("error allocating barrier: %m\n");
		goto out;
	}
	if ((pthread_tbarrier_init(tbar, NULL, child_count, NULL, NULL))) {
		output("error initializing tbarrier: %m\n");
		goto out;
	}
#endif

	// block SIGCHLD
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGCHLD);
	if ((sigprocmask(SIG_BLOCK, &sa.sa_mask, NULL)) < 0) {
		output("error blocking SIGCHLD: %m\n");
		goto out;
	}

	memset(&sa, 0, sizeof(sa));
	sigfillset(&sa.sa_mask);
	sa.sa_sigaction = handle_child_exit;
	if (sigaction(SIGCHLD, &sa, NULL) < 0) {
		output("error setting SIGCHLD action: %m\n");
		goto out;
	}


	for (i = 0 ; i < child_count ; i++) {
		if ((cpid = fork()) == 0)
			return child_work(i, path);
		else if (cpid > 0)
			cpids[i] = cpid;
		else {
			output("error forking: %m\n");
		}
	}


	// unblock SIGCHLD
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGCHLD);
	if ((sigprocmask(SIG_UNBLOCK, &sa.sa_mask, NULL)) < 0) {
		output("error unblocking SIGCHLD: %m\n");
		goto out;
	}

	sigfillset(&signal_mask);
	sigdelset(&signal_mask, SIGCHLD);
	sigdelset(&signal_mask, SIGINT);
	sigdelset(&signal_mask, SIGPIPE);
	sigdelset(&signal_mask, SIGABRT);
	sigdelset(&signal_mask, SIGHUP);
	sigdelset(&signal_mask, SIGQUIT);
	sigdelset(&signal_mask, SIGALRM);

	ret = EXIT_SUCCESS;
	while (42) {
		int running_count = 0;

		sigsuspend(&signal_mask);
		for (i = 0 ; i < child_count ; i++) {
			if (cpids[i] != 0) {
				running_count++;
				if (children_exited)
					kill(cpids[i], SIGINT);
			}
		}
		if (running_count == 0)
			break;
	}

out:
#if USE_BARRIER
	if (tbar && tbar != MAP_FAILED)
		munmap(tbar, sizeof(pthread_tbarrier_t));
#endif

	return ret;
}
