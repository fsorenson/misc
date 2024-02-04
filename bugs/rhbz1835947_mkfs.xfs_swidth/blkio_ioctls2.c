/*
	Frank Sorenson <sorenson@redhat.com>, 2020

	interpose ioctl() to replace BLKIOMIN and BLKIOOPT
	return values, reproducing Red Hat bugzilla 1835947

	gcc blkio_ioctls2.c -o blkio_ioctls2.so -Wall -DDEBUG=0 -shared -fPIC -rdynamic -ldl

	# LD_PRELOAD=$(pwd)/blkio_ioctls2.so mkfs.xfs -f /dev/loop0

*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <linux/fs.h>
#include <stdarg.h>

#define output(args...) do { \
	dprintf(fileno(stderr), args); \
	fflush(stdout); \
} while (0)

#if DEBUG
#define debug_output(args...) do { \
        output(args); \
} while (0)

#ifndef CDROM_GET_CAPABILITY
#define CDROM_GET_CAPABILITY 0x5331
#endif
#ifndef XFS_IOC_DIOINFO
#define XFS_IOC_DIOINFO _IOC(_IOC_READ, 0x58, 0x1e, 0xc)
#endif
struct ioctl_names {
	unsigned long cmd;
	const char *name;
	int size;
} ioctls[] = {
	{ BLKIOOPT, "BLKIOOPT", 4 },
	{ BLKIOMIN, "BLKIOMIN", 4 },
	{ BLKGETSIZE64, "BLKGETSIZE64", 8 },
	{ BLKALIGNOFF, "BLKALIGNOFF", 4 },
	{ BLKPBSZGET, "BLKPBSZGET", 4 },
	{ BLKSSZGET, "BLKSSZGET", 4 },
	{ BLKBSZSET, "BLKBSZSET", 4 },
	{ BLKDISCARD, "BLKDISCARD", 4 },
	{ BLKFLSBUF, "BLKFLSBUF", 0 },
	{ CDROM_GET_CAPABILITY, "CDROM_GET_CAPABILITY", 0 },
	{ XFS_IOC_DIOINFO, "XFS_IOC_DIOINFO", 0 },
};

#define ARRAY_SIZE(_a) (sizeof(_a)/sizeof(_a[0]))
const char *ioctl_name(unsigned long cmd) {
	int i;

	for (i = 0 ; i < ARRAY_SIZE(ioctls) ; i++) {
		if (ioctls[i].cmd == cmd)
			return ioctls[i].name;
	}
	return "UNKNOWN";
}
int ioctl_size(unsigned long cmd) {
	int i;

	for (i = 0 ; i < ARRAY_SIZE(ioctls) ; i++) {
		if (ioctls[i].cmd == cmd)
			return ioctls[i].size;
	}
	return 8;
}

#else
#define debug_output(args...) do { \
} while (0)
#endif

typedef int (*ioctl_t)(int fd, unsigned long request, ...);

static struct funcs {
	ioctl_t ioctl;
} real_funcs  = {
	NULL,
};

#define get_func(_handle, _func) ({ \
	char *error; \
	void *_ret = dlsym(_handle, #_func); \
	if ((error = dlerror()) != NULL) { \
		output("%s getting %s\n", error, #_func); \
		exit(EXIT_FAILURE); \
	} \
	_ret; })

int ioctl(int fd, unsigned long req, ...) {
	unsigned long *arg_addr;
	va_list ap;
	int ret;

	if (!real_funcs.ioctl) {
		void *handle = RTLD_NEXT;

		dlerror(); /* clear out any existing errors */
		real_funcs.ioctl = get_func(handle, ioctl);
	}

	va_start(ap, req);
	arg_addr = va_arg(ap, typeof(arg_addr));
	va_end(ap);

	ret = real_funcs.ioctl(fd, req, arg_addr);

	if (req == BLKIOMIN) {
		unsigned int val = *(unsigned int *)arg_addr;

		*(unsigned int *)arg_addr = 524288;
		output("BLKIOMIN result: %u => %u\n", val, *(unsigned int *)arg_addr);

		ret = 0;
	} else if (req == BLKIOOPT) {
		unsigned int val = *(unsigned int *)arg_addr;

		*(unsigned int *)arg_addr = 262144;
		output("BLKIOOPT result: %u => %u\n", val, *(unsigned int *)arg_addr);

		ret = 0;
	} else if (arg_addr) {
		debug_output("%s result: %lu\n", ioctl_name(req),
			ioctl_size(req) == 4 ? *(unsigned int *)arg_addr :
			ioctl_size(req) == 0 ? 0 :
				*(unsigned long *)arg_addr);
	} else {
		debug_output("%s returned %d\n", ioctl_name(req), ret);
	}
	return ret;
};
