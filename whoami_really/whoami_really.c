#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/fsuid.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

#define _PASTE(a,b) a##b
#define PASTE(a,b) _PASTE(a,b)

#define _PASTE3(a,b,c) a##b##c
#define PASTE3(a,b,c) _PASTE3(a,b,c)

#define _PASTE4(a,b,c,d) a##b##c##d
#define PASTE4(a,b,c,d) _PASTE4(a,b,c,d)

#define __STR(s...)	#s
#define _STR(s...)	__STR(s)
#define STR(s)		_STR(s)

#define show_id_old(type) do { \
	printf("\t" #type ": %u\n", PASTE(get, type)()); \
} while (0)
#define show_id_old2(ext, type) do { \
	printf("\t" #ext#type "id: %u\n", PASTE4(get, ext, type, id)()); \
} while (0)
#define show_id(ugid) do { \
	PASTE(ugid,_t) ugid = PASTE(get, ugid)(); \
	printf("\t" #ugid ": %u -> '%s'\n", ugid, \
		PASTE(idtoname_,ugid)(ugid)); \
} while (0)
#define show_uid(uid) show_id(uid)
#define show_gid(gid) show_id(gid)

#define show_resid_old(type, ug) do { \
	PASTE(ug,id_t) PASTE3(r,ug,id), PASTE3(e,ug,id), PASTE3(s,ug,id); \
	PASTE3(getres,ug,id)(&PASTE3(r,ug,id), &PASTE3(e,ug,id), &PASTE3(s,ug,id)); \
	printf("\t" STR(PASTE3(type,ug,id)) ": %u\n", PASTE3(type,ug,id)); \
} while (0)
#define show_resid(type, ugid) do { \
	PASTE(ugid,_t) PASTE(r,ugid), PASTE(e,ugid), PASTE(s,ugid); \
	PASTE(getres,ugid)(&PASTE(r,ugid), &PASTE(e,ugid), &PASTE(s,ugid)); \
	printf("\t" STR(PASTE(type,ugid)) ": %u -> '%s'\n", PASTE(type,ugid), \
		PASTE(idtoname_,ugid)(PASTE(type,ugid)) \
			); \
} while (0)
#define show_ruid(gid) show_resid(r, uid)
#define show_euid(gid) show_resid(e, uid)
#define show_suid(gid) show_resid(s, uid)
#define show_rgid(gid) show_resid(r, gid)
#define show_egid(gid) show_resid(e, gid)
#define show_sgid(gid) show_resid(s, gid)

#define show_fsid_old(type) do { \
	printf("\tfs" #type ": %u\n", PASTE(setfs, type)(-1)); \
} while (0)
#define show_fsid(ugid) do { \
	PASTE(ugid,_t) ugid = PASTE(setfs,ugid)(-1); \
	printf("\tfs" #ugid ": %u - '%s'\n", ugid, PASTE(idtoname_,ugid)(ugid)); \
} while (0)
#define show_fsuid(uid) show_fsid(uid)
#define show_fsgid(gid) show_fsid(gid)

char *idtoname_uid(uid_t uid) {
	static long pwsize = 0, pwsize_incr = 0;
	static char *buf = NULL;
	struct passwd *pwd = NULL, pwdbuf;

	if (pwsize_incr == 0) {
		pwsize = pwsize_incr = sysconf(_SC_GETPW_R_SIZE_MAX);
		buf = malloc(pwsize);
	}
retry:
	if (getpwuid_r(uid, &pwdbuf, buf, pwsize, &pwd) != 0) {
		if (errno == ERANGE) {
			char *tmp;
			pwsize += pwsize_incr;
			if ((tmp = realloc(buf, pwsize)) == NULL) {
				printf("error reallocating: %m\n");
				exit(EXIT_FAILURE);
			}
			buf = tmp;
			goto retry;
		} else {
			printf("error getting passwd: %m\n");
			exit(EXIT_FAILURE);
		}
	}
	if (pwd == NULL)
		return "*UNKNOWN*";
	return pwd->pw_name;
}

char *idtoname_gid(gid_t gid) {
	static long grsize = 0, grsize_incr = 0;
	static char *buf = NULL;
	struct group *group = NULL, groupbuf;

	if (grsize_incr == 0) {
		grsize = grsize_incr = sysconf(_SC_GETGR_R_SIZE_MAX);
		buf = malloc(grsize);
	}
retry:
	if (getgrgid_r(gid, &groupbuf, buf, grsize, &group) != 0) {
		if (errno == ERANGE) {
			char *tmp;
			grsize += grsize_incr;
			if ((tmp = realloc(buf, grsize)) == NULL) {
				printf("error reallocating: %m\n");
				exit(EXIT_FAILURE);
			}
			buf = tmp;
			goto retry;
		} else {
			printf("error getting group: %m\n");
			exit(EXIT_FAILURE);
		}
	}
	if (group == NULL)
		return "*UNKNOWN*";
	return group->gr_name;
}

int main(int argc, char *argv[]) {
//	getgrgid_r(getgid(), &group, grbuf, grsize, 
/*
printf("uid %d -> %s\n", 100, idtoname_uid(100));
printf("gid %d -> %s\n", 9000000, idtoname_gid(9000000));
printf("gid %d -> %s\n", 11, idtoname_gid(11));
printf("gid %d -> %s\n", 1001, idtoname_gid(1001));
*/

	printf("uid:\n");
//	show_id_old(uid);
//	show_id_old2(,u);
	show_id(uid);
	show_uid(uid);
/*
	show_id_old(euid);
	show_id_old2(e,u);

	show_resid_old(r, u);
	show_resid_old(e, u);
	show_resid_old(s, u);
	show_fsid_old(uid);

	show_resid(r, uid);
	show_resid(e, uid);
	show_resid(s, uid);
*/

	show_ruid(uid);
	show_euid(uid);
	show_suid(uid);


	show_fsid(uid);

	printf("gid:\n");

//	show_id_old(gid);
//	show_id_old2(,g);
	show_id(gid);
	show_gid(gid);
/*
	show_id_old(egid);
	show_id_old2(e,g);

	show_resid_old(r, g);
	show_resid_old(e, g);
	show_resid_old(s, g);
	show_fsid_old(gid);

	show_resid(r, gid);
	show_resid(e, gid);
	show_resid(s, gid);
*/

	show_rgid(gid);
	show_egid(gid);
	show_sgid(gid);


	show_fsid(gid);
	show_fsgid(gid);

	int grp_count;
	if ((grp_count = getgroups(0, NULL)) > 0) {
		gid_t *groups = calloc(grp_count, sizeof(gid_t));
		int ret, i;

		if ((ret = getgroups(grp_count, groups)) > 0) {
			if (ret == grp_count) {
				printf("%d groups:\n", grp_count);
				for (i = 0 ; i < grp_count ; i++) {
					printf("\t%u -> '%s'\n", groups[i], idtoname_gid(groups[i]));
				}
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

