/*
	Frank Sorenson - <sorenson@redhat.com>, 2020

	attempt to hit nfs client bug while handling fatal errors
		asynchronously.  In particular, we attempt to trigger
		writeback to a deleted-sillyrenamed file when the
		writeback is failing due to EDQUOT


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
		# gcc /var/tmp/bz1826123-2.c -o /var/tmp/bz1826123-2

	 * change to the user
		# su - user1
	
	 * start the reproducer, giving the base path of the mount:
		[user1@testvm ~]$ /var/tmp/bz1826123-2 /mnt/test

	the reproducer will spawn as many as 100 child threads, each of which will:
		open a file inside the base path
		unlink the newly-created file
		perform 32 KiB writes up to 10 MiB file size
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <errno.h>
#include <syscall.h>

#define KiB (1024)
#define MiB (KiB * KiB)

#define FILE_SIZE (10 * MiB)
#define BUF_SIZE (32 * KiB)
#define TOTAL_WRITES (FILE_SIZE / BUF_SIZE)

#define MAX_CHILDREN 100

static char *buf = NULL;
static char *base_path = NULL;
static int base_dfd;
static int child_count = 0;
static pid_t cpids[MAX_CHILDREN];

static inline pid_t gettid(void) {
	return (pid_t)syscall(SYS_gettid);
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
		if (WIFSTOPPED(status)) {
			kill(cpid, SIGINT);
			kill(cpid, SIGCONT);
		} else if (WIFEXITED(status) || WIFSIGNALED(status)) {
			cpids[child_id] = 0;
			child_count--;
		}
	}
}

void do_child_work(void) {
	pid_t mytid = gettid();
	struct sigaction sa;
	char *filename;
	int fd;
	int i;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &sa, NULL);

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
		goto retry_unlink;
	}
	for (i = 0 ; i < TOTAL_WRITES ; i++) {
		write(fd, buf, BUF_SIZE);
	}
	raise(SIGSTOP);
}

int main(int argc, char *argv[]) {
	pid_t cpid;
	struct sigaction sa;
	sigset_t signal_mask;
	int child_id;

	if (argc != 2) {
		printf("usage: %s <base_directory>\n", argv[0]);
		return EXIT_FAILURE;
	}
	base_path = argv[1];

	if ((base_dfd = open(base_path, O_RDONLY|O_DIRECTORY)) < 0) {
		printf("unable to open directory '%s': %m\n", base_path);
		return EXIT_FAILURE;
	}

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &handle_child;
	sigaction(SIGCHLD, &sa, NULL);

	sigfillset(&signal_mask);
	sigdelset(&signal_mask, SIGCHLD);

	buf = malloc(BUF_SIZE);
	memset(buf, 0x55, BUF_SIZE);

	for (child_id = 0 ; child_id < MAX_CHILDREN ; child_id++)
		cpids[child_id] = 0;
	while (42) {
		if (child_count < MAX_CHILDREN) {
			for (child_id = 0 ; child_id < MAX_CHILDREN ; child_id++) {
				if (cpids[child_id] == 0)
					break;
			}
			if (child_id >= MAX_CHILDREN) { /* shouldn't happen */
				printf("ERROR: unable to find available child slot: %d running\n", child_count);
				return EXIT_FAILURE;
			}
			if ((cpid = fork()) == 0) {
				do_child_work();
				return EXIT_FAILURE;
			}
			cpids[child_id] = cpid;
			child_count++;
		} else
			usleep(10);
	}

        return EXIT_SUCCESS;
}
