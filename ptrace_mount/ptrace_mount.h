#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __SOS_HOOKS_H__
#define __SOS_HOOKS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>


#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#define nop()   __asm__ __volatile__ ("nop")
#define PASTE(a, b) a##b
#define XSTR(a) #a

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)


#if TRACE_SYSCALLS
#define trace_syscall(args...) do { \
	outout(args); \
} while (0)
#else
#define trace_syscall(args...) do { } while (0)
#endif

#if DEBUG
#define debug_output(args...) do { \
	output(args); \
} while (0)
#else
#define debug_output(args...) do { \
} while (0)
#endif

struct config {
        pid_t child;
        pid_t parent;
	pid_t sos_pid;

        regex_t proc_pid_comm_regex;
        bool initializing;
        bool initialized;
        bool child_exited;
};
extern struct config config;

#include "ptrace_defs.h"

//#define replace_this_path(_path) (!strncmp(_path, "/proc", 5) || !strncmp(_path, "/etc", 4) || !strncmp(_path, "/sys", 4))

#define debug_report_syscall(_syscall) do { \
        debug_output("syscall: %s (%d)\n", #_syscall, PASTE(SYS_, _syscall)); \
} while (0)

//static inline int path_exists(const char *path) {
//	struct stat st;
//	return (stat(path, &st) == 0);
//}

#endif
