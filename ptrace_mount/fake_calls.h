#ifndef __FAKE_CALLS_H__
#define __FAKE_CALLS_H__

//#include "sos_hooks.h"
#include "ptrace_mount.h"
#include <sys/stat.h>
#include <sys/wait.h>


int fake_calls_init(void);

//       #include <sys/mount.h>

int fake_mount(const char *source, const char *target,
	const char *filesystemtype, unsigned long mountflags,
	const void *data);

#endif
