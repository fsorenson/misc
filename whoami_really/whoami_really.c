#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/fsuid.h>
#include <errno.h>

#define _PASTE(a,b) a##b
#define PASTE(a,b) _PASTE(a,b)

#define __STR(s...)	#s
#define _STR(s...)	__STR(s)
#define STR(s)		_STR(s)

#define RES_DESC_r "real "
#define RES_DESC_e "effective "
#define RES_DESC_s "saved "

#define UG_DESC_WIDTH "13"
#define UG_WIDTH "7"

#define show_id(ugid) do { \
	PASTE(ugid,_t) ugid = PASTE(get, ugid)(); \
	printf("\t%" UG_DESC_WIDTH "s: %" UG_WIDTH "u -> '%s'\n", #ugid, ugid, \
		PASTE(idtoname_,ugid)(ugid)); \
} while (0)
#define show_uid(uid) show_id(uid)
#define show_gid(gid) show_id(gid)

#define show_resid(type, ugid) do { \
	PASTE(ugid,_t) PASTE(r,ugid), PASTE(e,ugid), PASTE(s,ugid); \
	PASTE(getres,ugid)(&PASTE(r,ugid), &PASTE(e,ugid), &PASTE(s,ugid)); \
	printf("\t%" UG_DESC_WIDTH "s: %" UG_WIDTH "u -> '%s'\n", PASTE(RES_DESC_,type) "" STR(ugid), \
		PASTE(type,ugid), PASTE(idtoname_,ugid)(PASTE(type,ugid))); \
} while (0)

#define show_ruid(gid) show_resid(r, uid)
#define show_euid(gid) show_resid(e, uid)
#define show_suid(gid) show_resid(s, uid)
#define show_rgid(gid) show_resid(r, gid)
#define show_egid(gid) show_resid(e, gid)
#define show_sgid(gid) show_resid(s, gid)

#define show_fsid(ugid) do { \
	PASTE(ugid,_t) ugid = PASTE(setfs,ugid)(-1); \
	printf("\t%" UG_DESC_WIDTH "s: %" UG_WIDTH "u -> '%s'\n", STR(PASTE(fs,ugid)), \
		ugid, PASTE(idtoname_,ugid)(ugid)); \
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
	int grp_count;

	printf("uid:\n");
	show_uid(uid);

	show_ruid(uid);
	show_euid(uid);
	show_suid(uid);

	show_fsuid(uid);

	printf("gid:\n");
	show_gid(gid);

	show_rgid(gid);
	show_egid(gid);
	show_sgid(gid);

	show_fsgid(gid);

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
	} else if (grp_count == 0)
		printf("\tuser is not a member of any groups?\n");
	else
		printf("error occurred while getting groups: %m\n");

	return EXIT_SUCCESS;
}
