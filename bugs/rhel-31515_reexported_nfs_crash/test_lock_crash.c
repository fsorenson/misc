/*
	Frank Sorenson <sorenson@redhat.com>, 2024

	test program used when replicating Red Hat issue RHEL-31515,
	  a crash in nfsd while testing a lock on a re-exported nfs v3
	  mount simultaneously from both local system and a client
	  mounting the reexported filesystem.


	The reproducer requires 3 test systems and this test program:

	system 1 (nfs server):
	  # mkdir /exports
	  # touch /exports/testfile
	  /etc/exports:
	    /exports *(rw,no_root_squash)
	  # exportfs -av

	system 2 (nfs client + server):
	  # mkdir /exports
	  # mount system1:/exports /exports -overs=3
	  /etc/exports:
	    /exports *(rw,no_root_squash,fsid=50)
	  # exportfs -av  copy test_lock_crash.c to /tmp
	  # gcc /tmp/test_lock_crash.c -o /tmp/test_lock_crash
	  # /tmp/test_lock_crash /exports/testfile

	system 3 (nfs client):
	  # mkdir /mnt
	  # mount system2:/exports /mnt -overs=4  copy test_lock_crash.c to /tmp
	  # gcc /tmp/test_lock_crash.c -o /tmp/test_lock_crash  # /tmp/test_lock_crash /mnt/testfile


	The test program will repeatedly test and obtain a lock on the specified
	  file, then release the lock again.  When executed simultaneously on the
	  local intermediate system and on a client of the re-exported filesystem,
	  this soon induces a crash in nfsd:

	PID: 49117    TASK: ffff947b17a44000  CPU: 10   COMMAND: "nfsd"
	    [exception RIP: nlmclnt_setlockargs+0x3a]
	    RIP: ffffffffc07590ba  RSP: ffffa052045efd38  RFLAGS: 00010286
	...
	 #8 [ffffa052045efd50] nlmclnt_proc at ffffffffc075935a [lockd]
	 #9 [ffffa052045efda8] nfsd4_lockt at ffffffffc07a7443 [nfsd]
	#10 [ffffa052045efdf8] nfsd4_proc_compound at ffffffffc07936f1 [nfsd]
	#11 [ffffa052045efe58] nfsd_dispatch at ffffffffc077ecee [nfsd]
	#12 [ffffa052045efe80] svc_process_common at ffffffffc06b4320 [sunrpc]
	#13 [ffffa052045efed8] svc_process at ffffffffc06b4637 [sunrpc]
	#14 [ffffa052045efef0] nfsd at ffffffffc077e663 [nfsd]
	#15 [ffffa052045eff10] kthread at ffffffff8491eb44

	the crash occurs while dereferencing a struct file->f_inode inside
	  locks_inode() in the following code:

	125 static void nlmclnt_setlockargs(struct nlm_rqst *req, struct file_lock *fl)
	126 {
	127         struct nlm_args *argp = &req->a_args;
	128         struct nlm_lock *lock = &argp->lock;
	129         char *nodename = req->a_host->h_rpcclnt->cl_nodename;
	130 
	131         nlmclnt_next_cookie(&argp->cookie);
	132         memcpy(&lock->fh, NFS_FH(locks_inode(fl->fl_file)), sizeof(struct nfs_fh));

	due to a zero-value fl->fl_file:

	crash> file_lock.fl_file ffff947a8afa1bd8
	  fl_file = 0x0,
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

int main(int argc, char *argv[]) {
	struct flock fl = {
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
		.l_type = F_WRLCK
	};
	int type = F_WRLCK, fd;
	char *path;

	if (argc != 2) {
		output("usage: %s <test_file>\n", argv[0]);
		return EXIT_FAILURE;
	}
	path = argv[1];

	if ((fd = open(path, O_CREAT|O_RDWR|O_NONBLOCK, 0644)) < 0) {
		output("failed to open lockfile '%s': %m\n", path);
		output("usage: %s <test_file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	while (42) {
		fl.l_type = type;

		while ((fcntl(fd, F_SETLK, &fl)) == -1) {
			if (errno == EAGAIN) {
				fcntl(fd, F_GETLK, &fl);
				output("lock held by %d\n", fl.l_pid);
			} else {
				output("error setting lock on '%s': %m\n", path);
				return EXIT_FAILURE;
			}
		}
		output("%c", type == F_WRLCK ? 'W' : 'R');

		fl.l_type = F_UNLCK;
		fcntl(fd, F_SETLK, &fl);

		type = type == F_WRLCK ? F_RDLCK : F_WRLCK;	
	}
	close(fd); // yeah, I realize we'll never get here

	return EXIT_SUCCESS;
}
