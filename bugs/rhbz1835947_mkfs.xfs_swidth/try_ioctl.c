#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	int fd;
	unsigned long l;
	uid_t uid;
	gid_t gid;

printf("starting up!!!\n\n");
fflush(stdout);
fflush(stderr);

	uid = getuid();
fflush(stdout);
fflush(stderr);
	printf("\n\nuid: %d\n\n", uid);
fflush(stdout);
fflush(stderr);
	uid = geteuid();
fflush(stdout);
	printf("euid: %d\n", uid);
fflush(stdout);


	gid = getgid();
fflush(stdout);
fflush(stderr);
	printf("\n\ngid: %d\n\n", gid);
fflush(stdout);
fflush(stderr);
	gid = getegid();
fflush(stdout);
	printf("egid: %d\n", gid);
fflush(stdout);



	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		printf("error opening: %m\n");
		return EXIT_FAILURE;
	}

	printf("calling ioctl with address %p\n", &l);
	if ((ioctl(fd, BLKIOMIN, &l)) < 0) {
		printf("ioctl(BLKIOMIN) returned: %m\n");
//		return EXIT_FAILURE;
	}

	printf("my result address was %p\n", &l);
	printf("BLKIOMIN: %lu\n", l & 0xffffffff);


	if ((ioctl(fd, BLKIOOPT, &l)) < 0) {
		printf("ioctl(BLKIOOPT) returned: %m\n");
//		return EXIT_FAILURE;
	}
	printf("BLKIOOPT: %lu\n", l & 0xffffffff);


///home/sorenson/RH/rhkernel_trees/rhel7/fs/xfs/libxfs/xfs_fs.h:#define XFS_IOC_DIOINFO		_IOR ('X', 30, struct dioattr)

//#include "/home/sorenson/RH/rhkernel_trees/rhel7/fs/xfs/libxfs/xfs_fs.h"
//#define XFS_IOC_DIOINFO _IOR ('X', 30, struct dioattr)
#define XFS_IOC_DIOINFO _IOC(_IOC_READ, 0x58, 0x1e, 0xc)

	printf("XFS_IOC_DIOINFO is %lx\n", XFS_IOC_DIOINFO);

	printf("trying ioctl %lx\n", _IOC(_IOC_READ, 0x58, 0x1e, 0xc));

	if ((ioctl(fd, _IOC(_IOC_READ, 0x58, 0x1e, 0xc), 0x7fff64c59490), &l) < 0) {
		printf("not sure what ioctl %lx is \n", _IOC(_IOC_READ, 0x58, 0x1e, 0xc));
	}

	return EXIT_SUCCESS;
}
