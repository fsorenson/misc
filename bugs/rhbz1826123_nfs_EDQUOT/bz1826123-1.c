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

		(mostly arbitrary)
		soft: 49920
		hard: 99840

	 * set ownership on the exported filesystem (or a subdir) to the user
		# chown -R user1:user1 /exports/vde

		# quota -s -u user1
		Disk quotas for user user1 (uid 501): 
		     Filesystem   space   quota   limit   grace   files   quota   limit   grace
		       /dev/vde      0K  49920K  99840K               1       0       0        

	 * export the filesystem:
		/exports *(no_acl,rw,no_root_squash,sec=sys)
		/exports/vde *(rw,no_root_squash,sec=sys)


	on client:
	 * mount the exported filesystem:
		# mkdir -p /mnt/test
	 	# mount server:/exports/vde /mnt/test -overs=3,rsize=65536,wsize=65536,relatime,sec=sys

	* compile the reproducer program:
		# gcc /var/tmp/bz1826123-1.c -o /var/tmp/bz1826123-1

	 * change to the user
		# su - user1
	
	 * start the reproducer, giving the base path of the mount:
		[user1@testvm ~]$ /var/tmp/bz1826123-1 /mnt/test


	the reproducer will spawn as many as 100 child threads
		each child thread will spawn its own child which will:
			open a file inside the base path
			unlink the newly-created file
			perform 32 KiB writes up to 10 MiB file size
			send itself SIGSTOP
		the child thread will


		, each spawning its own child

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
	pid_t pid;
	int status;

	while ((pid = wait4(-1, &status, WNOHANG, NULL)) != -1) {
		if (pid == 0)
			return;
		child_count--;
	}
}

void do_child_work(void) {
	pid_t mytid = gettid();
	char *filename;
	int fd;
	int i;

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

void middleman(void) {
	struct sigaction sa;
	pid_t cpid, pid;
	int status;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &sa, NULL);

	if ((cpid = fork()) == 0) {
		do_child_work();
		exit(-1);
	}

	while (42) {
		if ((pid = wait4(cpid, &status, WNOHANG, NULL)) != -1) {
			if (pid == cpid && WIFSTOPPED(status))
				break;
		}
		usleep(10);
	}
	kill(cpid, SIGINT);
	kill(cpid, SIGCONT);
	while (42) {
		if ((pid = wait4(cpid, &status, WNOHANG, NULL)) != -1) {
			if (pid == cpid && WIFEXITED(status))
				break;
		}
		usleep(10);
	}
	exit(0);
}

int main(int argc, char *argv[]) {
	pid_t cpid;
	struct sigaction sa;
	sigset_t signal_mask;
	int i;

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

	for (i = 0 ; i < MAX_CHILDREN ; i++)
		cpids[i] = 0;
	while (42) {
		if (child_count < MAX_CHILDREN) {
			for (i = 0 ; i < MAX_CHILDREN ; i++) {
				if (cpids[i] == 0)
					break;
			}

			if ((cpid = fork()) == 0) {
				middleman();
				return EXIT_FAILURE;
			}
			cpids[i] = cpid;
			child_count++;
		} else
			usleep(10);
	}

        return EXIT_SUCCESS;
}
