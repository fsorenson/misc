#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/file.h>


typedef enum { lock_type_read = 0, lock_type_write = 1, lock_type_rw = 2 } lock_type_t;
typedef enum { lock_method_flock = 0, lock_method_posix = 1, lock_method_ofd = 2, lock_method_lease } lock_method_t;

#define lock_type_flags(ltype) ( \
	(ltype == lock_type_read) ? F_RDLCK : \
	(ltype == lock_type_write) ? F_WRLCK : \
	F_RDLCK | F_WRLCK \
)
#define lock_type_string(ltype) ( \
	(ltype == lock_type_read) ? "READ" : \
	(ltype == lock_type_write) ? "WRITE" : \
	"READ-WRITE" \
)
#define whence_string(whence) ( \
	(whence == SEEK_SET) ? "beginning of file" : \
	(whence == SEEK_CUR) ? "current file position" : \
	"end of file" \
)
int set_fd_blocking(int fd, bool blocking) {
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (blocking)
		flags &= ~O_NONBLOCK;
	else
		flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
	return 0;
}


int do_fcntl_lock(int fd, lock_type_t locktype, lock_method_t lm, bool wait) {
	struct flock fl = {
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
		.l_type = lock_type_flags(locktype),
	};
	int cmd;

	if (lm == lock_method_posix)
		cmd = wait ? F_SETLKW : F_SETLK;
	else
		cmd = wait ? F_OFD_SETLKW : F_OFD_SETLK;

	if ((fcntl(fd, cmd, &fl)) < 0) {
		printf("Error setting lock: %m\n");
		return -errno;
	}
	return 0;
}
int do_fcntl_testlk(int fd, lock_type_t locktype, lock_method_t lm) {
	struct flock fl = {
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
		.l_type = lock_type_flags(locktype),
	};
	int cmd = (lm == lock_method_posix) ? F_GETLK : F_OFD_GETLK;

	if ((fcntl(fd, cmd, &fl)) < 0) {
		printf("Error getting lock: %m\n");
		return -errno;
	}
	if (fl.l_type == F_UNLCK)
		printf("file is not locked for %s\n",
			(locktype == lock_type_read) ? "READ" :
			(locktype == lock_type_write) ? "WRITE" :
			"READ or WRITE");
	else {
		printf("file is locked for %s", lock_type_string(fl.l_type));
		if (fl.l_pid != -1)
			printf(" by pid %d", fl.l_pid);
		printf(" - conflicting lock: %s lock, offset %ld from %s",
			lock_type_string(fl.l_type), fl.l_start, whence_string(fl.l_whence));
		if (fl.l_len == 0)
			printf(" through end of file\n");
		else
			printf(" for length %ld\n", fl.l_len);
	}

	return 0;
}

int do_posix_lock(int fd, lock_type_t locktype, bool wait) {
#if 0
	struct flock fl = {
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
		.l_type = locktype == lock_type_read ? F_RDLCK : F_WRLCK,
	};

	if ((fcntl(fd, wait ? F_SETLKW : F_SETLK, &fl)) < 0) {
		printf("Error setting lock: %m\n");
		return -errno;
	}
	return 0;
#endif
	return do_fcntl_lock(fd, locktype, lock_method_posix, wait);
}
int do_posix_unlock(int fd, bool wait) {
	struct flock fl = {
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
		.l_type = F_UNLCK,
	};
//		.l_type = locktype == lock_type_read ? F_RDLCK : F_WRLCK,

	if ((fcntl(fd, wait ? F_SETLKW : F_SETLK, &fl)) < 0) {
		printf("Error unlocking: %m\n");
		return -errno;
	}
	return 0;
}
int do_posix_testlk(int fd, lock_type_t locktype) {
	return do_fcntl_testlk(fd, locktype, lock_method_posix);
}


int do_ofd_lock(int fd, lock_type_t locktype, bool wait) {
#if 0
	struct flock fl = {
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
		.l_type = locktype == lock_type_read ? F_RDLCK : F_WRLCK,
	};

	if ((fcntl(fd, wait ? F_OFD_SETLKW : F_OFD_SETLK, &fl)) < 0) {
		printf("Error setting lock: %m\n");
		return -errno;
	}
	return 0;
#endif
	return do_fcntl_lock(fd, locktype, lock_method_ofd, wait);
}
int do_ofd_unlock(int fd, bool wait){
	struct flock fl = {
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
		.l_type = F_UNLCK,
	};

	if ((fcntl(fd, wait ? F_OFD_SETLKW : F_OFD_SETLK, &fl)) < 0) {
		printf("Error unlocking: %m\n");
		return -errno;
	}
	return 0;
}
int do_ofd_testlk(int fd, lock_type_t locktype) {
	return do_fcntl_testlk(fd, locktype, lock_method_ofd);
}

int do_flock_lock(int fd, lock_type_t locktype, bool wait) {
	int operation = locktype == lock_type_read ? LOCK_SH : LOCK_EX;

	if (!wait)
		operation |= LOCK_NB;
	 return flock(fd, operation);
}
int do_flock_unlock(int fd) {
	return flock(fd, LOCK_UN);
}
int do_flock_testlk(int fd) {
	printf("can't test flocks()\n");
	return -ENOTSUP;
}


int do_lease(int fd, lock_type_t locktype, bool wait) {
	if (fcntl(fd, F_SETLEASE,
		locktype == lock_type_read ? F_RDLCK : F_WRLCK) < 0) {
		printf("Error setting lease: %m\n");
		return -errno;
	}
	return 0;
}
int do_release(int fd, bool wait) {
	if (fcntl(fd, F_SETLEASE, F_UNLCK) < 0) {
		printf("Error setting lease: %m\n");
		return -errno;
	}
	return 0;
}
int do_lease_test(int fd, lock_type_t locktype) {
	int ret = fcntl(fd, F_GETLEASE);

	if (ret == F_UNLCK)
		printf("There are no leases\n");
	else if (ret == F_RDLCK)
		printf("READ lease exists\n");
	else if (ret == F_WRLCK)
		printf("WRITE lease exists\n");
	else
		printf("F_GETLEASE failed: %m\n");

	return 0;
}


int do_test_locks(int fd) {
	printf("    flock test: ");
	do_flock_testlk(fd);

	printf("    posix lock test, READ: ");
	do_posix_testlk(fd, lock_type_read);
	printf("    posix lock test, WRITE: ");
	do_posix_testlk(fd, lock_type_write);
	printf("    posix lock test, READ-WRITE: ");
	do_posix_testlk(fd, lock_type_rw);


	printf("    OFD lock test, READ: ");
	do_ofd_testlk(fd, lock_type_read);
	printf("    OFD lock test, WRITE: ");
	do_ofd_testlk(fd, lock_type_write);
	printf("    OFD lock test, READ-WRITE: ");
	do_ofd_testlk(fd, lock_type_rw);


	printf("    lease test, READ: ");
	do_lease_test(fd, lock_type_read);
	printf("    lease test, WRITE: ");
	do_lease_test(fd, lock_type_write);
	return 0;
}

int main(int argc, char *argv[]) {
	int fd;

	if ((fd = open("testfile", O_RDWR|O_CREAT, 0666)) < 0) {
		printf("Error opening file: %m\n");
		return EXIT_FAILURE;
	}

#if 0
	if (do_posix_lock(fd, lock_type_rw, false)) {
		printf("could not set posix read-write lock\n");
	} else {
		printf("read-write posix lock succeeded\n");
		sleep(100);
		do_posix_unlock(fd, true);
	}
	printf("\n");
#endif

#if 0
	if (do_ofd_lock(fd, lock_type_rw, false)) {
		printf("could not set OFD read-write lock\n");
	} else {
		printf("read-write OFD lock succeeded\n");
		sleep(100);
		do_ofd_unlock(fd, true);
	}
	printf("\n");
#endif


//	printf("flock test: ");
//	do_flock_testlk(fd);

#if 0
	printf("flock shared: ");
	if (do_flock_lock(fd, lock_type_read, false))
		printf("unable to set shared flock\n");
	else {
		printf("shared flock succeeded\n");
		do_flock_unlock(fd);
	}

	printf("flock exclusive: ");
	if (do_flock_lock(fd, lock_type_write, false))
		printf("unable to set exclusive flock\n");
	else {
		printf("exclusive flock succeeded\n");
		do_flock_unlock(fd);
	}
	printf("\n");
#endif

#if 0
	printf("\n");
	set_fd_blocking(fd, 0);
	do_lease(fd, lock_type_write, false);
	do_lease_test(fd, lock_type_write);
	do_release(fd, false);
	set_fd_blocking(fd, 1);

#endif




	printf("taking flock READ lock\n");
	do_flock_lock(fd, lock_type_read, 0);
	do_test_locks(fd);
	do_flock_unlock(fd);
	printf("taking flock WRITE lock\n");
	do_flock_lock(fd, lock_type_write, 0);
	do_test_locks(fd);
	do_flock_unlock(fd);

	printf("taking posix READ lock\n");
	do_posix_lock(fd, lock_type_read, 0);
	do_test_locks(fd);
	do_posix_unlock(fd, false);
	printf("taking posix WRITE lock\n");
	do_posix_lock(fd, lock_type_write, 0);
	do_test_locks(fd);
	do_posix_unlock(fd, false);


	printf("taking OFD READ lock\n");
	do_ofd_lock(fd, lock_type_read, 0);
	do_test_locks(fd);
	do_ofd_unlock(fd, false);
	printf("taking OFD WRITE lock\n");
	do_ofd_lock(fd, lock_type_write, 0);
	do_test_locks(fd);
	do_ofd_unlock(fd, false);


	printf("taking READ lease\n");
	set_fd_blocking(fd, 0);
	do_lease(fd, lock_type_read, true);
	do_test_locks(fd);
	do_release(fd, false);
	printf("taking WRITE lease\n");
	do_lease(fd, lock_type_write, false);
	do_test_locks(fd);
	do_release(fd, false);
	set_fd_blocking(fd, 1);



	printf("\n");











	return EXIT_SUCCESS;
}
