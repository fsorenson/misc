/*
	Frank Sorenson <sorenson@redhat.com>, 2017

	Stat a path after calling setreuid() for a range of uids

	usage:  stat_as.c  <path> <start_uid> <end_uid>
		start_uid and end_uid should be numeric, and are inclusive
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sched.h>

/* whether to fork off a new process for each stat() call */
/* attempt simultaneity (sp?) */

#define mb()    __asm__ __volatile__("mfence" ::: "memory")
#define nop()   __asm__ __volatile__ ("nop")

struct shared_info_struct {
	int go;
};

int main(int argc, char *argv[]) {
	char *path;
	uid_t start_uid, end_uid;
	uid_t i;
	struct stat st;
	pid_t cpid;
	struct shared_info_struct *shared_info;

	if (argc != 4) {
		printf("usage: %s <path> <start_uid> <end_uid>\n", argv[0]);
		return EXIT_FAILURE;
	}
	path = argv[1];
	start_uid = strtol(argv[2], NULL, 10);
	end_uid = strtol(argv[3], NULL, 10);

	shared_info = mmap(NULL, sizeof(struct shared_info_struct), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	shared_info->go = 0;

	printf("calling stat on '%s' with uids %u through %u\n", path, start_uid, end_uid);
	for (i = start_uid ; i < end_uid + 1 ; i ++) {
		if ((cpid = fork()) == 0) {
			while (!shared_info->go)
				sched_yield();
			setreuid(-1, i);
			stat(path, &st);
			break;
		}
	}
	shared_info->go = 1;
	mb();

	return EXIT_SUCCESS;
}
