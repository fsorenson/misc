
#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
#include <string.h>
#include <errno.h>


#define mb()    __asm__ __volatile__("mfence" ::: "memory")
#define nop()   __asm__ __volatile__ ("nop")


#define CL_ADDR	"192.168.122.71"

#define	S1_ADDR	"192.168.122.73"
#define SRC1	"vm1:/exports"
#define TGT1	"/mnt/vm1"

#define S2_ADDR	"192.168.122.72"
#define	SRC2	"vm2:/exports"
#define	TGT2	"/mnt/vm2"


#define	OPTS	"vers=4.0,sec=sys"


/* use one of these */
//#define MIG_OPT ""
//#define MIG_OPT ",migration"
#define	MIG_OPT	",nomigration"

#define MOUNT_ATTEMPTS 10

struct test_info {
	volatile int go;
	char *mnt1_src;
	char *mnt1_tgt;
	char *mnt1_opts;
	dev_t mnt1_parent_dev;

	char *mnt2_src;
	char *mnt2_tgt;
	char *mnt2_opts;
	dev_t mnt2_parent_dev;

	char *mnt_opts;
};

static struct test_info *test_info;

dev_t check_mp(char *mp, char **canon_mp) {
	struct stat st, parent_st;;
	char *parent, *canon_parent;

	*canon_mp = realpath(mp, NULL);
	if (stat(*canon_mp, &st) == -1) {
		printf("stat of mountpoint '%s' ('%s') failed: %s\n",
			mp, *canon_mp, strerror(errno));
		free(canon_mp);
		exit(EXIT_FAILURE);
	}
	if (! S_ISDIR(st.st_mode)) {
		printf("mountpoint '%s' ('%s') is not a directory\n",
			mp, *canon_mp);
		free(canon_mp);
		exit(EXIT_FAILURE);
	}
	asprintf(&parent, "%s/..", *canon_mp);
	canon_parent = realpath(parent, NULL);
	free(parent);

	stat(canon_parent, &parent_st);
	free(canon_parent);

	if (st.st_dev != parent_st.st_dev) {
		printf("mountpoint '%s' ('%s') already appears to have a filesystem mounted\n",
			mp, *canon_mp);
		free(*canon_mp);
		exit(EXIT_FAILURE);
	}
	return parent_st.st_dev;
}

int check_success(void) {
	struct stat st1, st2;

	stat(test_info->mnt1_tgt, &st1);
	if (st1.st_dev == test_info->mnt1_parent_dev)
		return 0;

	stat(test_info->mnt2_tgt, &st2);
	if (st2.st_dev == test_info->mnt2_parent_dev)
		return 0;

	if (st1.st_dev == st2.st_dev)
		return 1;

	return 0;
}

int main(int argc, char *argv[]) {
	int attempt = 0;
	pid_t cpid;
	int ret;

	test_info = mmap(NULL, sizeof(struct test_info), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	test_info->mnt1_src = SRC1;
	test_info->mnt2_src = SRC2;
	test_info->mnt1_parent_dev = check_mp(TGT1, &test_info->mnt1_tgt);
	test_info->mnt2_parent_dev = check_mp(TGT2, &test_info->mnt2_tgt);

	asprintf(&test_info->mnt1_opts, "%s,clientaddr=%s,addr=%s" MIG_OPT,
		OPTS, CL_ADDR, S1_ADDR);
	asprintf(&test_info->mnt2_opts, "%s,clientaddr=%s,addr=%s" MIG_OPT,
		OPTS, CL_ADDR, S2_ADDR);

	while (attempt < MOUNT_ATTEMPTS) {
		test_info->go = 1;
		printf("#%d: ", ++attempt);
		fflush(stdout);

		if ((cpid = fork()) == 0) { /* child */
			test_info->go = 0;
			mb();
			while (!test_info->go)
				nop();

			ret = mount(test_info->mnt1_src, test_info->mnt1_tgt, "nfs", 0, test_info->mnt1_opts);
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
			ret = mount(test_info->mnt2_src, test_info->mnt2_tgt, "nfs", 0, test_info->mnt2_opts);
			if (ret == -1) {
				printf("error mounting in parent: %m\n");
				break;
			}

			while (test_info->go)
				nop();

			ret = check_success();
			if (ret)
				break;

			printf("FAIL\n");
			fflush(stdout);
			umount(test_info->mnt1_tgt);
			umount(test_info->mnt2_tgt);
		}
	} /* while */
	free(test_info->mnt1_tgt);
	free(test_info->mnt2_tgt);
	free(test_info->mnt1_opts);
	free(test_info->mnt2_opts);

	munmap(test_info, sizeof(struct test_info));
	if (ret) {
		printf("SUCCESS\n");
		printf("Successfully reproduced the bug on attempt %d\n", attempt);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}
