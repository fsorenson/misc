#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>


#define mb()    __asm__ __volatile__("mfence" ::: "memory")
#define nop()   __asm__ __volatile__ ("nop")


#define ADDR1	"192.168.122.73"
#define S1	ADDR1 ":/exports"
#define MP1	"/mnt/vm1"

#define ADDR2	"192.168.122.72"
#define S2	ADDR2 ":/exports"
#define MP2	"/mnt/vm2"

#define CL_ADDR	"192.168.122.71"


#define SHARED_OPTS "vers=4.0,nomigration,port=2049,rsize=131072,wsize=131072,sec=sys"
#define MOUNT_ATTEMPTS 500

struct test_info {
	volatile int go;
};

struct test_info *test_info;

dev_t check_mount(char *mp) {
	char *canon_mp;
	char *parent;
	char *canon_parent;
	struct stat st;
	struct stat parent_st;

	canon_mp = canonicalize_file_name(mp);
	stat(canon_mp, &st);
	if (! S_ISDIR(st.st_mode)) {
		printf("requested mountpoint '%s' resolves to '%s', but is not a directory\n",
			mp, canon_mp);
		free(canon_mp);
		exit(EXIT_FAILURE);
	}

	asprintf(&parent, "%s/..", canon_mp);
	canon_parent = canonicalize_file_name(parent);
	free(parent);

	stat(canon_parent, &parent_st);
	free(canon_parent);
	free(canon_mp);

	if (st.st_dev == parent_st.st_dev) {
		printf("'%s' does not appear to be a mountpoint\n", mp);
		exit(EXIT_FAILURE);
	}

	return st.st_dev;
}

int main(int argc, char *argv[]) {
	pid_t cpid;
	int ret;
	int attempt = 0;

	test_info = mmap(NULL, sizeof(struct test_info), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	while (attempt < MOUNT_ATTEMPTS) {
		test_info->go = 1;
		printf("#%d: ", ++attempt);
		fflush(stdout);

		if ((cpid = fork()) == 0) { /* child */
			test_info->go = 0;
			mb();
			while (!test_info->go)
				nop();

			ret = mount("192.168.122.73:/exports", "/mnt/vm1", "nfs", 0, SHARED_OPTS ",addr=192.168.122.73");
			test_info->go = 0;
			mb();
			if (ret == -1) {
				printf("error mounting in child: %m\n");
				return EXIT_FAILURE;
			}
			return EXIT_SUCCESS;
		} else {
			while (test_info->go)
				nop();
			test_info->go = 1;
			mb();
			ret = mount("192.168.122.72:/exports", "/mnt/vm2", "nfs", 0, SHARED_OPTS ",addr=192.168.122.72");
			if (ret == -1) {
				printf("error mounting in parent: %m\n");
				return EXIT_FAILURE;
			}

			while (test_info->go)
				nop();

			dev_t mp1_dev;
			dev_t mp2_dev;

			mp1_dev = check_mount("/mnt/vm1");
			mp2_dev = check_mount("/mnt/vm2");

			if (mp1_dev == mp2_dev) {
				printf("SUCCESS\n");
				printf("Successfully reproduced the bug\n");
				return EXIT_SUCCESS;
			}
			printf("FAIL\n");
			fflush(stdout);
			umount("/mnt/vm1");
			umount("/mnt/vm2");
		}
	} /* while */
//	mount("vm1:/exports", "/mnt/vm1", "nfs", 0, "vers=4.0,addr=192.168.122.73,clientaddr=192.168.122.71,rsize=131072,wsize=131072,sec=sys");
//	mount("vm2:/exports", "/mnt/vm2", "nfs", 0, "vers=4.0,addr=192.168.122.72,clientaddr=192.168.122.71,rsize=131072,wsize=131072,sec=sys");


	printf("failed to reproduce the bug after %d attempts\n", attempt);
	return EXIT_FAILURE;
}
