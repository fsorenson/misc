/*
	Frank Sorenson - <sorenson@redhat.com>, 2020

	attempt to hit nfs client bug while handling fatal errors
		asynchronously.  In particular, we attempt to trigger
		writeback to a deleted-sillyrenamed file when the
		writeback is failing due to EDQUOT, and the writing
		process has died (causing the write attempt to become
		async)

	on client and server:
	* create user with same uid
		# getent passwd user1
		user1:x:501:501::/home/user1:/bin/bash

	on server:

	* set up disk quota for the user on a filesystem
		/dev/vde on /exports/vde type xfs (rw,relatime,seclabel,attr2,inode64,logbufs=8,logbsize=32k,usrquota,grpquota)

		(mostly arbitrary; but the values probably should not divide cleanly by 32 KiB--the write size)
		soft: 29920
		hard: 49840

	* set ownership on the exported filesystem (or a subdir) to the user
		# chown -R user1:user1 /exports/vde

		# quota -s -u user1
		Disk quotas for user user1 (uid 501): 
		     Filesystem   space   quota   limit   grace   files   quota   limit   grace
		       /dev/vde      0K  29920K  49840K               1       0       0        

	* export the filesystem:
		/exports *(no_acl,rw,no_root_squash,sec=sys)
		/exports/vde *(rw,no_root_squash,sec=sys)


	on client:
	* mount the exported filesystem:
		# mkdir -p /mnt/test
	 	# mount server:/exports/vde /mnt/test -overs=3,rsize=65536,wsize=65536,relatime,sec=sys

	* compile the reproducer program:
		# gcc /var/tmp/bz1826123-3.c -o /var/tmp/bz1826123-3
	  can also define number of children, file size, and size/write at compile-time:
		# gcc /var/tmp/bz1826123-3.c -o /var/tmp/bz1826123-3 -D MAX_CHILDREN=100 -D WRITE_SIZE="(32 * KiB)" -D FILE_SIZE="(100 * MiB)"

	* change to the user (or pass uid/gid on command line as shown below)
		# su - user1
	
	* start the reproducer, giving the base path of the mount:
		[user1@testvm ~]$ /var/tmp/bz1826123-3 /mnt/test
	   or also giving uid and gid of the user for setgid()/setuid():
	   	[root@testvm ~]# /var/tmp/bz1826123-3 501 501 /mnt/test

	the reproducer will spawn as many as <MAX_CHILDREN> (default 100) child threads, each of which will:
		open a file inside the base path
		unlink the newly-created file
		perform <WRITE_SIZE> (default 1 MiB) writes up to <FILE_SIZE> (default 10 MiB) file size
		send itself SIGSTOP
	when the main loop receives the signal that a child has stopped or exited, it will:
		child has stopped:
			kill the child process with SIGINT
			send the child process SIGCONT
		child has exited:
			reuse that child slot to start a new child

*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <errno.h>
#include <syscall.h>
#include <sys/mman.h>

#define KiB (1024)
#define MiB (KiB * KiB)

#ifndef FILE_SIZE
# define FILE_SIZE (10 * MiB)
#endif

#ifndef WRITE_SIZE
# define WRITE_SIZE (1 * MiB)
#endif
#define TOTAL_WRITES (FILE_SIZE / WRITE_SIZE)

#ifndef MAX_CHILDREN
# define MAX_CHILDREN 100
#endif

// print pretty dots for each running child, remove dots when child reaped (ala 'ping -f')
#ifndef SHOW_DOTS
# define SHOW_DOTS 0
#endif

static char *buf = NULL;
static char *base_path = NULL;
static int base_dfd;
static int child_count = 0;
pid_t *cpids;
static bool parent_exit = false;


static inline pid_t gettid(void) {
	return (pid_t)syscall(SYS_gettid);
}


static void reap_child(int child_id) {
	cpids[child_id] = 0;
	child_count--;
#if SHOW_DOTS
	printf("\b \b");
	fflush(stdout);
#endif
}
static void handle_child(int sig) {
	int status, child_id;
	pid_t cpid;

	while ((cpid = wait4(-1, &status, WNOHANG|WUNTRACED, NULL)) != -1) {
		if (cpid == 0) /* no pids changed status */
			return;
		for (child_id = 0 ; child_id < MAX_CHILDREN ; child_id++) {
			if (cpid == cpids[child_id])
				break;
		}
		if (child_id >= MAX_CHILDREN) {
			printf("error: unable to reap child pid %d\n", cpid);
			continue;
		}
		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			reap_child(child_id);
		} else if (WIFSTOPPED(status)) {
			if (
				(kill(cpid, SIGINT) < 0 || kill(cpid, SIGCONT) < 0) &&
				errno == ESRCH) {
				reap_child(child_id);
			}
		}
	}
}
static void interrupt_parent(int sig) {
	int child_id;

	parent_exit = true;
	for (child_id = 0 ; child_id < MAX_CHILDREN ; child_id++) {
		if (cpids[child_id]) {
			kill(cpids[child_id], SIGINT);
			kill(cpids[child_id], SIGCONT);
		}
	}
}

void do_child_work(int child_id) {
	pid_t mytid = gettid();
	struct sigaction sa;
	char *filename;
	int fd;
	int i;

	while (cpids[child_id] != mytid)
		usleep(1);

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	asprintf(&filename, "testfile_pid_%d", mytid);

retry_open:
	if ((fd = openat(base_dfd, filename, O_CREAT|O_TRUNC|O_RDWR, 0644)) < 0) {
		if (errno == EDQUOT) {
			usleep(10);
			goto retry_open;
		}
		return; /* shrug */
	}
retry_unlink:
	if ((unlinkat(base_dfd, filename, 0)) < 0) {
		printf("error unlinking '%s': %m\n", filename);
		if (errno == ESTALE || errno == ENOENT) {
			return;
		}
		goto retry_unlink;
	}
	for (i = 0 ; i < TOTAL_WRITES ; i++) {
		write(fd, buf, WRITE_SIZE);
	}
	raise(SIGSTOP);
}

int main(int argc, char *argv[]) {
	pid_t cpid;
	struct sigaction sa;
	sigset_t signal_mask;
	int child_id;

	if (argc == 4) {
		uid_t uid = strtol(argv[1], NULL, 10);
		gid_t gid = strtol(argv[2], NULL, 10);

		if ((setgid(gid)) < 0) {
			printf("error calling setgid(%d): %m\n", gid);
			return EXIT_FAILURE;
		}
		if ((setuid(uid)) < 0) {
			printf("error calling setuid(%d): %m\n", uid);
			return EXIT_FAILURE;
		}
		base_path = argv[3];
	} else if (argc == 2) {
		base_path = argv[1];
	} else {
		printf("usage: %s [ <UID> <GID> ] <base_directory>\n", argv[0]);
		return EXIT_FAILURE;
	}

	if ((base_dfd = open(base_path, O_RDONLY|O_DIRECTORY)) < 0) {
		printf("unable to open directory '%s': %m\n", base_path);
		return EXIT_FAILURE;
	}

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &handle_child;
	sigaction(SIGCHLD, &sa, NULL);

	sa.sa_handler = &interrupt_parent;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	sigfillset(&signal_mask);
	sigdelset(&signal_mask, SIGCHLD);
	sigdelset(&signal_mask, SIGINT);
	sigdelset(&signal_mask, SIGTERM);

	buf = malloc(WRITE_SIZE);
	memset(buf, 0x55, WRITE_SIZE);


	cpids = mmap(NULL, sizeof(pid_t) * MAX_CHILDREN, PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_ANONYMOUS, -1, 0);

	for (child_id = 0 ; child_id < MAX_CHILDREN ; child_id++)
		cpids[child_id] = 0;

	while (! parent_exit) {
		if (child_count < MAX_CHILDREN) {
			for (child_id = 0 ; child_id < MAX_CHILDREN ; child_id++) {
search_next:
				if (cpids[child_id] == 0)
					break;
			}
			if (child_id >= MAX_CHILDREN) { /* shouldn't happen, but does... just restart */
				continue;
			}
			if ((cpid = fork()) == 0) {
				do_child_work(child_id);
				return EXIT_FAILURE;
			} else if (cpid < 0) {
				printf("failed to fork: %m\n");
				usleep(10);
				continue;
			}

			cpids[child_id] = cpid;
			child_count++;
#if SHOW_DOTS
			printf(".");
			fflush(stdout);
#endif
			child_id++;
			if (child_id < MAX_CHILDREN && child_count < MAX_CHILDREN) {
				goto search_next;
			}
		} else
			usleep(10);
	}
	printf("waiting for children to exit\n");
	while (child_count > 0) {
		usleep(10);

		child_count = 0;
		for (child_id = 0 ; child_id < MAX_CHILDREN ; child_id++)
			child_count += cpids[child_id] != 0 ? 1 : 0;
	}
	printf("exiting\n");
        return EXIT_SUCCESS;
}
