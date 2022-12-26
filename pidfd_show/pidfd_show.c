#define _GNU_SOURCE

/*
	Frank Sorenson <sorenson@redhat.com>, 2022
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/resource.h>

#include <termios.h>
#include <time.h>

#define free_mem(addr) do { \
	if (addr) \
		free(addr); \
	addr = NULL; \
} while (0)
#define close_fd(fd) do { \
	if (fd != -1) \
		close(fd); \
	fd = -1; \
} while (0)


int procfd = -1, proc_pid_fd = -1, proc_pid_fd_dfd = -1;

//int syscall(SYS_pidfd_open, pid_t pid, unsigned int flags);

int pidfd_open(pid_t pid, unsigned int flags) {
	return syscall(__NR_pidfd_open, pid, flags);
}
int pidfd_getfd(int pidfd, int targetfd, unsigned int flags) {
	return syscall(__NR_pidfd_getfd, pidfd, targetfd, flags);
}

struct tcflag_str_val {
	tcflag_t val;
	char *str;
};

#define TFLAG(s) (struct tcflag_str_val){ .val = s, .str = #s }

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

static struct tcflag_str_val termflags_I[] = {
	TFLAG(IGNBRK),
	TFLAG(BRKINT),
	TFLAG(IGNPAR),
	TFLAG(PARMRK),
	TFLAG(INPCK),
	TFLAG(ISTRIP),
	TFLAG(INLCR),
	TFLAG(IGNCR),
	TFLAG(ICRNL),
	TFLAG(IUCLC),
	TFLAG(IXON),
	TFLAG(IXANY),
	TFLAG(IXOFF),
	TFLAG(IMAXBEL),
	TFLAG(IUTF8),
};

static struct tcflag_str_val termflags_O[] = {
	TFLAG(OPOST),
	TFLAG(OLCUC),
	TFLAG(ONLCR),
	TFLAG(OCRNL),
	TFLAG(ONOCR),
	TFLAG(ONLRET),
	TFLAG(OFILL),
	TFLAG(OFDEL),
	TFLAG(NLDLY),
	TFLAG(CRDLY),
	TFLAG(TABDLY),
	TFLAG(BSDLY),
	TFLAG(VTDLY),
	TFLAG(FFDLY),
};

static struct tcflag_str_val termflags_C_CSIZE[] = {
	TFLAG(CS5),
	TFLAG(CS6),
	TFLAG(CS7),
	TFLAG(CS8),
};
static struct tcflag_str_val termflags_C[] = {
	TFLAG(CSIZE),
	TFLAG(CSTOPB),
	TFLAG(CREAD),
	TFLAG(PARENB),
	TFLAG(PARODD),
	TFLAG(HUPCL),
	TFLAG(CLOCAL),
	TFLAG(CIBAUD),
	TFLAG(CRTSCTS),

	TFLAG(CBAUD),
	TFLAG(CBAUDEX),
//	TFLAG(LOBLK), // not in Linux
	TFLAG(CMSPAR),
};

static struct tcflag_str_val termflags_L[] = {
	TFLAG(ISIG),
	TFLAG(ICANON),
	TFLAG(XCASE),
	TFLAG(ECHO),
	TFLAG(ECHOE),
	TFLAG(ECHOK),
	TFLAG(ECHONL),
	TFLAG(ECHOCTL),
	TFLAG(ECHOPRT),
	TFLAG(ECHOKE),
//	TFLAG(DEFECHO), // not in Linux
	TFLAG(FLUSHO),
	TFLAG(NOFLSH),
	TFLAG(TOSTOP),
	TFLAG(PENDIN),
	TFLAG(IEXTEN),
};

void DisplayTermFlags_I(tcflag_t flags) {
	int i;

	printf("    iflag = 0x%X: ", flags);
	for (i = 0 ; i < ARRAY_SIZE(termflags_I) ; i++)
		if (flags & termflags_I[i].val) printf("%s ", termflags_I[i].str);
	printf("\n");
}
void DisplayTermFlags_O(tcflag_t flags) {
	int i;
	printf("    oflag = 0x%X: ", flags);
	for (i = 0 ; i < ARRAY_SIZE(termflags_O) ; i++)
		if (flags & termflags_O[i].val) printf("%s ", termflags_O[i].str);
	printf("\n");
}

void DisplayTermFlags_C(tcflag_t flags) {
	int i;

	printf("    cflag = 0x%X: ", flags);
	for (i = 0 ; i < ARRAY_SIZE(termflags_C) ; i++) {
		if (termflags_C[i].val == CSIZE) {
			int j;
			for (j = 0 ; j < ARRAY_SIZE(termflags_C_CSIZE) ; j++)
				if ((flags & CSIZE) == termflags_C_CSIZE[j].val)
					printf("%s ", termflags_C_CSIZE[j].str);
		} else if (flags & termflags_C[i].val)
			printf("%s ", termflags_C[i].str);
	}
	printf("\n");
}
void DisplayTermFlags_L(tcflag_t flags) {
	int i;
	printf("    lflag = 0x%X: ", flags);
	for (i = 0 ; i < ARRAY_SIZE(termflags_L) ; i++)
		if (flags & termflags_L[i].val) printf("%s ", termflags_L[i].str);
	printf("\n");
}
static struct tcflag_str_val term_io_speeds[] = {
	TFLAG(B0),
	TFLAG(B50),
	TFLAG(B75),
	TFLAG(B110),
	TFLAG(B134),
	TFLAG(B150),
	TFLAG(B200),
	TFLAG(B300),
	TFLAG(B600),
	TFLAG(B1200),
	TFLAG(B1800),
	TFLAG(B2400),
	TFLAG(B4800),
	TFLAG(B9600),
	TFLAG(B19200),
	TFLAG(B38400),
	TFLAG(B57600),
	TFLAG(B115200),
	TFLAG(B230400),
};
void decode_speed(const char *IO_dir, const speed_t speed) {
	int i;
	for (i = 0 ; i < ARRAY_SIZE(term_io_speeds) ; i++)
		if (speed == term_io_speeds[i].val) {
			printf("    %s speed: %s\n", IO_dir, term_io_speeds[i].str);
			break;
		}
	printf("\n");
}
void show_term_ispeed(const struct termios *termios) {
	speed_t speed = cfgetispeed(termios);
	decode_speed("input", speed);
}
void show_term_ospeed(const struct termios *termios) {
	speed_t speed = cfgetospeed(termios);
	decode_speed("output", speed);
}
void show_term_settings(int fd) {
	struct termios termios;
	int ret;

	if ((ret = tcgetattr(fd, &termios)) < 0)
		return;

	DisplayTermFlags_I(termios.c_iflag);
	DisplayTermFlags_O(termios.c_oflag);
	DisplayTermFlags_C(termios.c_cflag);
	DisplayTermFlags_L(termios.c_lflag);
}


int do_show_pidfd_fd(pid_t pid, int pidfd, int targetfd) {
	char *link_buf = NULL, fd_str[10];
	struct stat st;
	int ret = EXIT_FAILURE, fd;

	if ((fd = pidfd_getfd(pidfd, targetfd, 0)) < 0) {
//		printf("error getting pid %d, pidfd %d, fd %d: %m\n", pid, pidfd, targetfd);
		goto out;
	}

	if ((fstatat(fd, "", &st, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) < 0) {
		printf("error with fstat on fd: %m\n");
		return EXIT_FAILURE;
	}

	printf("pid %d fd %d:\n", pid, targetfd);

	if (isatty(fd)) {
		char *tty_buf = NULL;
		if (!(tty_buf = malloc(255))) {
			printf("    TTY: name: UNKNOWN\n");
		} else {
			if ((ttyname_r(fd, tty_buf, 255)) < 0) {
				printf("    TTY: name: %m\n");
			} else {
				printf("    TTY: %s\n", tty_buf);
			}
		}
		show_term_settings(fd);

		free_mem(tty_buf);
	}

	printf("    File type:                ");
	switch (st.st_mode & S_IFMT) {
		case S_IFBLK:  printf("block device\n"); break;
		case S_IFCHR:  printf("character device\n"); break;
		case S_IFDIR:  printf("directory\n"); break;
		case S_IFIFO:  printf("FIFO/pipe\n"); break;
		case S_IFLNK:  printf("symlink\n"); break;
		case S_IFREG:  printf("regular file\n"); break;
		case S_IFSOCK: printf("socket\n"); break;
		default:       printf("unknown?\n"); break;
	}
	printf("    inode number: %ju\n", (uintmax_t)st.st_ino);
	printf("    mode: %jo\n", (uintmax_t)st.st_mode);
	printf("    link count: %ju\n",  (uintmax_t)st.st_nlink);
	printf("    ownership:  uid: %ju  gid: %ju\n", (uintmax_t)st.st_uid, (uintmax_t)st.st_gid);
	printf("    size: %jd bytes\n", (uintmax_t)st.st_size);
	printf("    blocks allocated: %jd\n", (uintmax_t)st.st_blocks);



	if (proc_pid_fd_dfd) {
		link_buf = malloc(4096);

		snprintf(fd_str, sizeof(fd_str) - 1, "%d", targetfd);
		if ((readlinkat(proc_pid_fd_dfd, fd_str, link_buf, 4096)) < 0) {
		} else {
			printf("    link => %s\n", link_buf);
		}
	}


/*
           printf("ID of containing device:  [%jx,%jx]\n",
                   (uintmax_t) major(sb.st_dev),
                   (uintmax_t) minor(sb.st_dev));

           printf("Preferred I/O block size: %jd bytes\n",
                   (intmax_t) sb.st_blksize);

           printf("Last status change:       %s", ctime(&sb.st_ctime));
           printf("Last file access:         %s", ctime(&sb.st_atime));
           printf("Last file modification:   %s", ctime(&sb.st_mtime));
*/

//       Since  Linux  2.6.39, pathname can be an empty string, in which case the call operates on the symbolic link referred to by dirfd (which should have been obtained using open(2) with
//       the O_PATH and O_NOFOLLOW flags).


//       int fstatat(int dirfd, const char *restrict pathname,
//                struct stat *restrict statbuf, int flags);

#if 0
	if ((stat
           struct stat {
               dev_t     st_dev;         /* ID of device containing file */
               ino_t     st_ino;         /* Inode number */
               mode_t    st_mode;        /* File type and mode */
               nlink_t   st_nlink;       /* Number of hard links */
               uid_t     st_uid;         /* User ID of owner */
               gid_t     st_gid;         /* Group ID of owner */
               dev_t     st_rdev;        /* Device ID (if special file) */
               off_t     st_size;        /* Total size, in bytes */
               blksize_t st_blksize;     /* Block size for filesystem I/O */
               blkcnt_t  st_blocks;      /* Number of 512B blocks allocated */

               /* Since Linux 2.6, the kernel supports nanosecond
                  precision for the following timestamp fields.
                  For the details before Linux 2.6, see NOTES. */

               struct timespec st_atim;  /* Time of last access */
               struct timespec st_mtim;  /* Time of last modification */
               struct timespec st_ctim;  /* Time of last status change */
#endif


	ret = EXIT_SUCCESS;
out:
	free_mem(link_buf);
	return ret;
}

int get_pid_maxfd(pid_t pid) {
	struct rlimit rlimit;

	if ((prlimit(pid, RLIMIT_NOFILE, NULL, &rlimit)) < 0) {
		printf("error getting rlimit for pid %d: %m\n", pid);
		return -1;
	}
	return rlimit.rlim_cur;
}

int main(int argc, char *argv[]) {
	int ret = EXIT_FAILURE, pidfd = -1, fd = -1;
	pid_t pid;

	if (argc == 3) {
		pid = strtol(argv[1], NULL, 10);
		fd = strtol(argv[2], NULL, 10);
	} else if (argc == 2) {
		pid = strtol(argv[1], NULL, 10);
	} else {
		printf("usage: %s <pid> [<fd>]\n", argv[0]);
		goto out;
	}

	if ((pidfd = pidfd_open(pid, 0)) < 0) {
		printf("error opening pidfd: %m\n");
		goto out;
	}

	if ((procfd = open("/proc", O_RDONLY|O_DIRECTORY)) < 0) {
		printf("error opening /proc directory: %m\n");
		goto out;
	}
	if ((proc_pid_fd = openat(procfd, argv[1], O_RDONLY|O_DIRECTORY)) < 0) {
	} else {
		if ((proc_pid_fd_dfd = openat(proc_pid_fd, "fd", O_RDONLY|O_DIRECTORY)) < 0) {
		} else {
		}
	}

	if (fd >= 0) {
		do_show_pidfd_fd(pid, pidfd, fd);
	} else {
		int max_fd = get_pid_maxfd(pid);
		if (max_fd != -1) {
			for (fd = 0 ; fd < max_fd ; fd++) {
				do_show_pidfd_fd(pid, pidfd, fd);
			}
		}
	}

	ret = EXIT_SUCCESS;

out:
	close_fd(proc_pid_fd_dfd);
	close_fd(proc_pid_fd);
	close_fd(procfd);


	return ret;
}

