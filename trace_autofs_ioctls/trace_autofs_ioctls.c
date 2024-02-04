#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/auto_dev-ioctl.h>

static int initialized = 0;

typedef int (*ioctl_t)(int fd, unsigned long request, void *arg, ...);
ioctl_t real_ioctl;

#define output(args...) do { \
	fprintf(stderr, args); \
	fflush(stderr); \
} while (0)

/* for dlsym lookups */
#define get_func(_handle, _func) ({ \
	char *error; \
	void *_ret = dlsym(_handle, #_func); \
	if ((error = dlerror()) != NULL) { \
		output("%s getting %s\n", error, #_func); \
		exit(EXIT_FAILURE); \
	} \
_ret; })

pid_t gettid(void) {
	return syscall(SYS_gettid);
}

void init(void) {
	void *handle = RTLD_NEXT;

	if (!initialized) {
		dlerror();

		real_ioctl = get_func(handle, ioctl);

		initialized = 1;
		output("initialized\n");
	}
}

#define get_param() ({ \
	struct autofs_dev_ioctl *adi; \
	va_list arg_ptr; \
	va_start(arg_ptr, request); \
	adi = va_arg(arg_ptr, struct autofs_dev_ioctl *); \
	va_end(arg_ptr); \
	adi; \
})

#define get_path0() do { \
	struct autofs_dev_ioctl *adi; \
	va_list arg_ptr; \
	va_start(arg_ptr, request); \
	adi = va_arg(arg_ptr, struct autofs_dev_ioctl *); \
	if (adi->size > sizeof(struct autofs_dev_ioctl)) \
		path = strdup(adi->path); \
	va_end(arg_ptr); \
} while (0);
#define get_path() do { \
	if (adi->size > sizeof(struct autofs_dev_ioctl)) \
		path = strdup(adi->path); \
} while (0)


int ioctl(int fd, unsigned long request, ...) {
	void *args = __builtin_apply_args();
	struct autofs_dev_ioctl *adi;
	char *path = NULL;
	bool unknown_ioctl = false;
	init();
	pid_t pid = getpid(), tid = gettid();

	adi = get_param();

	switch (request) {
		case AUTOFS_DEV_IOCTL_ISMOUNTPOINT:
			get_path();
//			output("ISMOUNTPOINT call %s\n", path); break;
			break;
		case AUTOFS_DEV_IOCTL_ASKUMOUNT:
			get_path();
//			output("ASKUMOUNT call %s\n", path); break;
			break;
		case AUTOFS_DEV_IOCTL_OPENMOUNT:
			get_path();
//			output("OPENMOUNT call %s\n", path); break;
			break;
		case AUTOFS_DEV_IOCTL_CLOSEMOUNT:
			get_path();
			output("CLOSEMOUNT call %s\n", path); break;
		case AUTOFS_DEV_IOCTL_TIMEOUT:
//			get_path();
//			output("TIMEOUT call %s\n", path); break;
			break;
		case AUTOFS_DEV_IOCTL_EXPIRE:
			get_path();
			output("EXPIRE call %s\n", path); break;
		case AUTOFS_DEV_IOCTL_VERSION:
			get_path();
			output("%d - VERSION %d.%d\n", tid, adi->ver_major, adi->ver_minor); break;
		case AUTOFS_DEV_IOCTL_PROTOVER:
//			output("PROTOVER call\n"); break;
			break;
		case AUTOFS_DEV_IOCTL_PROTOSUBVER:
//			output("PROTOSUBVER call\n"); break;
			break;
		case AUTOFS_DEV_IOCTL_CATATONIC:
			output("CATATONIC call %s\n", path); break;
		default:
			unknown_ioctl = true;
			output("***** unknown ioctl: %lx\n", request); break;
	}


	void *ret = __builtin_apply((void (*)())real_ioctl, args, 1000);
//	output("returned: %d\n", *(int *)(ret));


//	if (*(int *)ret != -1) {
	{
		switch (request) {
			case AUTOFS_DEV_IOCTL_ISMOUNTPOINT:
				if (*(int *)ret == 0)
					output("%d/%d - ISMOUNTPOINT %s returns devid: %x, magic: %x\n",
						pid, tid, path, adi->ismountpoint.out.devid, adi->ismountpoint.out.magic);
				else
					output("%d/%d - ISMOUNTPOINT %s - false\n", pid, tid, path);
				break;
			case AUTOFS_DEV_IOCTL_ASKUMOUNT:
				output("%d/%d - ASKUMOUNT '%s' returns %d - ask_umount: %d\n",
					pid, tid, path, *(int *)ret, adi->askumount.may_umount);
				break;
			case AUTOFS_DEV_IOCTL_OPENMOUNT:
				output("%d/%d - OPENMOUNT(%s) returns device %x\n", pid, tid, path, adi->openmount.devid);
				break;
			case AUTOFS_DEV_IOCTL_CLOSEMOUNT:
				output("%d/%d - CLOSEMOUNT %s\n", pid, tid, path); break;
			case AUTOFS_DEV_IOCTL_TIMEOUT:
				output("%d/%d - TIMEOUT() returns %lld\n", pid, tid, adi->timeout.timeout); break;
			case AUTOFS_DEV_IOCTL_EXPIRE:
				output("%d/%d - EXPIRE(%s) returns\n", pid, tid, path); break;
			case AUTOFS_DEV_IOCTL_VERSION:
//				output("%d - VERSION %s returns %d\n", tid, path, *(int *)ret); break;
				break;
			case AUTOFS_DEV_IOCTL_PROTOVER:
				output("PROTOVER returning %d\n", adi->protover.version); break;
			case AUTOFS_DEV_IOCTL_PROTOSUBVER:
				output("PROTOSUBVER returning %d\n", adi->protosubver.sub_version); break;
			case AUTOFS_DEV_IOCTL_CATATONIC:
				output("CATATONIC return %s\n", path); break;
			default:
				output("unknown ioctl: %lx\n", request); break;
		}
	}




	if (path != NULL)
		free(path);

	__builtin_return(ret);


//	return real_ioctl(fd, request, arg);
}


__attribute__((constructor)) static void init_hook(void) {
	init();
}
