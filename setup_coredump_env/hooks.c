#define _GNU_SOURCE

/*
	gcc hook.c -o hook.so -shared -fPIC -rdynamic -ldl -g -O0
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/cdefs.h>

//#include <linux/openat2.h>  /* Definition of RESOLVE_* constants */
//#include <sys/syscall.h>    /* Definition of SYS_* constants */

#define REPLACE_CHROOT 0
#define REPLACE_GETUIDS 1
#define REPLACE_CHOWNS 1

#define get_func(_handle, _func) ({ \
	char *error; \
	void *_ret = dlsym(_handle,#_func); \
	if ((error = dlerror()) != NULL) { \
		fprintf(stderr, "%s getting %s\n", error, #_func); \
		exit(EXIT_FAILURE); \
	} \
	_ret; \
})
#define set_func_addr(_func) ({ \
	char *error; \
	void *handle = RTLD_NEXT; \
\
	real_funcs._func = get_func(handle, _func); \
})

#define free_mem(ptr) do { \
	if (ptr) \
		free(ptr); \
	ptr = NULL; \
} while (0)
#define close_fd(fd) do { \
	if (fd < 0) \
		close(fd); \
	fd = -1; \
} while (0)

static char *root_path = NULL;	// the current 'root' path (only meaningful after a chroot()
static char *pwd = NULL;	// the current working directory; relative to 'root_path', and only meaningful after a chroot()

typedef int (*chroot_t)(const char *path);

#if REPLACE_CHOWNS
	typedef int (*chown_t)(const char *pathname, uid_t owner, gid_t group);
	typedef int (*fchown_t)(int fd, uid_t owner, gid_t group);
	typedef int (*lchown_t)(const char *pathname, uid_t owner, gid_t group);
	typedef int (*fchownat_t)(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
#endif

typedef uid_t (*getuid_t)(void);

struct funcs {
#if REPLACE_CHROOT
	chroot_t chroot;
#endif

#if REPLACE_CHOWNS
	chown_t chown;
	fchown_t fchown;
	lchown_t lchown;
	fchownat_t fchownat;
#endif
#if REPLACE_GETUIDS
	getuid_t getuid;
	getuid_t geteuid;
	getuid_t getgid;
	getuid_t getegid;
#endif
};
struct funcs real_funcs;


struct slock {
	unsigned int dispensor;
	unsigned int serving;
};
struct config {
//	bool initializing;
	bool initialized;
	struct slock init_lock;
};
static struct config config = {
//	.initializing = false,
	.initialized = false,
	.init_lock = { .dispensor = 0, .serving = 0 },
};

int spin_lock(struct slock *slock) {
	unsigned int my_ticket = __atomic_fetch_add(&slock->dispensor, 1, __ATOMIC_SEQ_CST);
	unsigned int currently_serving;

	while ((currently_serving = __atomic_load_n(&slock->serving, __ATOMIC_SEQ_CST)) != my_ticket)
		usleep(50000 * (my_ticket - currently_serving));
	return 0;
}
int spin_unlock(struct slock *slock) {
	__atomic_fetch_add(&slock->serving, 1, __ATOMIC_SEQ_CST);
	return 0;
}

void __init(void) {
	void *handle;
	int ret;

	if (config.initialized)
		return;

	spin_lock(&config.init_lock);

	if (config.initialized)
		return;

//	config.initializing = true;
	handle = RTLD_NEXT;

	dlerror(); /* clear out any existing errors */

#if REPLACE_CHROOT
	real_funcs.chroot = get_func(handle, chroot);
#endif
#if REPLACE_GETUIDS
	real_funcs.getuid = get_func(handle, getuid);
	real_funcs.geteuid = get_func(handle, geteuid);
	real_funcs.getgid = get_func(handle, getgid);
	real_funcs.getegid = get_func(handle, getegid);
#endif
#if REPLACE_CHOWNS
	set_func_addr(chown);
	set_func_addr(fchown);
	set_func_addr(lchown);
	set_func_addr(fchownat);
#endif
	config.initialized = true;
	spin_unlock(&config.init_lock);
}
void init(void) {
	if (config.initialized)
		return;

	__init();
}

#if REPLACE_GETUIDS
uid_t getuid(void) {
	init();
	return 0;
}
uid_t geteuid(void) {
	init();
	return 0;
}
uid_t getgid(void) {
	init();
	return 0;
}
uid_t getegid(void) {
	init();
	return 0;
}
#endif

#if REPLACE_CHROOT
int chroot(const char *path) {
	char *tmp = NULL;

	init();
	if (root_path) { // chroot within a chroot...
		if (path[0] == '/')
			asprintf(&tmp, "%s/%s", root_path, path);
		else
			asprintf(&tmp, "%s/%s/%s", root_path, pwd, path);

		free(root_path);
		root_path = tmp;
	} else
		root_path = strdup(path);

	free_mem(pwd);
	pwd = strdup("/");

	return 0;
}
#endif
#if REPLACE_CHOWNS
	int chown(const char *pathname, uid_t owner, gid_t group) {
		real_funcs.chown(pathname, owner, group);
		return 0;
	}
	int fchown(int fd, uid_t owner, gid_t group) {
		real_funcs.fchown(fd, owner, group);
		return 0;
	}
	int lchown(const char *pathname, uid_t owner, uid_t group) {
		real_funcs.lchown(pathname, owner, group);
		return 0;
	}
	int fchownat(int dirfd, const char *pathname, uid_t owner, uid_t group, int flags) {
		real_funcs.fchownat(dirfd, pathname, owner, group, flags);
		return 0;
	}
#endif
