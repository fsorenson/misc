#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/fsuid.h>

#define _PASTE(a,b) a##b
#define PASTE(a,b) _PASTE(a,b)

#define _PASTE3(a,b,c) a##b##c
#define PASTE3(a,b,c) _PASTE3(a,b,c)

#define __STR(s...)	#s
#define _STR(s...)	__STR(s)
#define STR(s)		_STR(s)

#define show_id(type) do { \
	printf("\t" #type ": %u\n", PASTE(get, type)()); \
} while (0)

#define show_resid(type, ug) do { \
	PASTE(ug,id_t) PASTE3(r,ug,id), PASTE3(e,ug,id), PASTE3(s,ug,id); \
	PASTE3(getres,ug,id)(&PASTE3(r,ug,id), &PASTE3(e,ug,id), &PASTE3(s,ug,id)); \
	printf("\t" STR(PASTE3(type,ug,id)) ": %u\n", PASTE3(type,ug,id)); \
} while (0)

#define show_fsid(type) do { \
	printf("\tfs" #type ": %u\n", PASTE(setfs, type)(-1)); \
} while (0)

int main(int argc, char *argv[]) {
	printf("uid:\n");
	show_id(uid);
	show_id(euid);
	show_resid(r, u);
	show_resid(e, u);
	show_resid(s, u);
	show_fsid(uid);

	printf("gid:\n");
	show_id(gid);
	show_id(egid);

	show_resid(r, g);
	show_resid(e, g);
	show_resid(s, g);
	show_fsid(gid);

	int grp_count;
	if ((grp_count = getgroups(0, NULL)) > 0) {
		gid_t *groups = calloc(grp_count, sizeof(gid_t));
		int ret, i;

		if ((ret = getgroups(grp_count, groups)) > 0) {
			if (ret == grp_count) {
				printf("%d groups:\n", grp_count);
				for (i = 0 ; i < grp_count ; i++)
					printf("\t%u\n", groups[i]);
			} else
				printf("error occurred while getting groups: %m\n");
		}
		free(groups);
	} else if (grp_count == 0) {
		printf("user is not a member of any groups?\n");
	} else
		printf("error occurred while getting groups: %m\n");
/*
	getresuid
		getresgid
		getegid

          real user ID and saved set-user-ID.  This switching is done via calls to seteuid(2), setreuid(2), or  setresuid(2).
          A  set-group-ID program performs the analogous tasks using setegid(2), setregid(2), or setresgid(2).  A process can
          obtain its saved set-user-ID (set-group-ID) using getresuid(2) (getresgid(2)).
*/

	return EXIT_SUCCESS;
}

