#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <string.h>
#include <limits.h>
#include <syscall.h>
#include <sys/user.h>
#include <sys/mman.h>

//#include "sos_hooks.h"
#include "ptrace_mount.h"


#if DEBUG
#define debug_output(args...) do { \
	output(args); \
} while (0)
#else
#define debug_output(args...) do { \
} while (0)
#endif


/* for dlsym lookups */
#define get_func(_handle, _func) ({ \
	char *error; \
	void *_ret = dlsym(_handle, #_func); \
	if ((error = dlerror()) != NULL) { \
		output("%s getting %s\n", error, #_func); \
		exit(EXIT_FAILURE); \
	} \
_ret; })

typedef int (*mount_t)(const char *source, const char *target,
	const char *filesystemtype, unsigned long mountflags,
	const void *data);


struct funcs {

	mount_t mount;
};

struct funcs real_funcs;

struct config config = {
	.initializing = false,
	.initialized = false
};

static void init(void) {
	void *handle = RTLD_NEXT;
	int ret;

	if (config.initialized)
		return;
	while (config.initializing)
		nop();
	if (config.initialized)
		return;

	config.initializing = true;

	debug_output("initializing tracer\n");

	dlerror();
	real_funcs.mount = get_func(handle, mount);

	config.initialized = true;
	config.initializing = false;
	debug_output("probably initialized\n");
}

__attribute__((constructor)) static void init_hooks(void) {
	init();
}
