#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <execinfo.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <regex.h>
#include <string.h>
#include <limits.h>
#include <syscall.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

//#include "sos_hooks.h"
//#include "fake_calls.h"

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#if DEBUG
#define debug_output(args...) do { \
        output(args); \
} while (0)
#else
#define debug_output(args...) do { \
} while (0)
#endif

#define nop()   __asm__ __volatile__ ("nop")

struct config {
	pid_t parent;
	pid_t child;
        bool initializing;
        bool initialized;
        bool child_exited;
	bool child_initialized;
} config = {
	.initializing = false,
	.initialized = false,
	.child_exited = false,
	.child_initialized = false,
};

#if 1
#define catch_return(_cpid) do { \
	int _status; \
	ptrace(PTRACE_SYSCALL, _cpid, NULL, NULL); \
	waitpid(_cpid, &_status, 0); \
	if (WIFEXITED(_status)) \
		config.child_exited = true; \
} while (0)
#else
#define catch_return(_cpid) do { \
} while (0)
#endif

#define PROC_PID_COMM_REGEX_STRING "^/proc/([1-9][0-9]*)/comm$"
#define MAX_REGEX_ERROR 0x100

//#define replace_this_path(_path) (!strncmp(_path, "/proc", 5) || !strncmp(_path, "/etc", 4))
#define path_is_proc_pid_comm(_path) ({ \
	regmatch_t regex_matches[5]; \
	int regex_ret; \
	\
	output("checking whether '%s' is a /proc/pid/comm\n", _path); \
	if ((regex_ret = regexec(&config.proc_pid_comm_regex, _path, 1, regex_matches, 0)) != 0) { \
		char error_message[MAX_REGEX_ERROR]; \
		regerror(regex_ret, &config.proc_pid_comm_regex, error_message, MAX_REGEX_ERROR); \
		output("error matching regex '%s' for '%s': %s\n", PROC_PID_COMM_REGEX_STRING, _path, error_message); \
		regex_ret = 0; \
	} else \
		regex_ret = strtol(_path + regex_matches[0].rm_so, NULL, 10); \
	regex_ret; \
})

#define can_access(_addr) ({ \
	unsigned char vector[1]; \
	int ret = mincore((void *)(_addr & ~(4096 - 1)), 4096, vector); \
	if (ret == 0) \
		output("mincore of 0x%llx was successful...  result: %d\n", _addr, (int)ret); \
	else \
		output("mincore of 0x%llx returned %d: %m\n", _addr, ret); \
	(ret == 0); \
})

#define try_output_str(_reg, _addr) do { \
	if (can_access(_addr)) { \
		char *_s = (char *)_addr; \
		output("reg '%s' (%p): reachable, string: '%s'\n", #_reg, _s, _s); \
		if (*((char *)_addr)) { \
			output("reg '%s' (%p): reachable, string: '%s'\n", #_reg, (char *)_addr, (char *)_addr); \
		} \
		else \
			output("reg '%s': reachable, but first character is null value: %02x\n", #_reg, *(char *)_addr); \
	} else \
		output("reg '%s': not reachable (%m)\n", #_reg); \
} while (0)


#define try_replace_path(_cpid, _syscall, _regs, _reg) ({ \
	debug_output("%s (%llu) checking whether to replace '%s'\n", #_syscall, _regs.orig_rax, (char *)_regs._reg); \
output("%s reg %s expected to work, reg rdi: ", #_syscall, #_reg); \
try_output_str(rdi, _regs.rdi); \
output("%s reg %s expected to work, reg rsi: ", #_syscall, #_reg); \
try_output_str(rsi, _regs.rsi); \
	if (replace_this_path((char *)_regs._reg)) { \
		debug_output("%s('%s' -> '%s')\n", #_syscall, (char *)_regs._reg, (char *)(_regs._reg + 1)); \
		_regs._reg = _regs._reg + 1; \
		ptrace(PTRACE_SETREGS, _cpid, NULL, &_regs); \
	} \
})

#define debug_report_syscall(_syscall) do { \
	debug_output("syscall: %s (%d)\n", #_syscall, PASTE(SYS_, _syscall)); \
} while (0)

#define debug_report_syscall_case(_syscall) \
	case PASTE(SYS_, _syscall): \
		debug_report_syscall(_syscall); \
		catch_return(cpid); \
		break;


//		ptrace(PTRACE_SYSCALL, cpid, NULL, NULL); break; /* catch return */
//		debug_report_syscall(_syscall) ; break

#define output_syscall_hit(_cpid, _syscall, _regs, _reg) ({ \
	char *tmp_buf = read_string(_cpid, _regs._reg); \
	int replace = replace_this_path(tmp_buf); \
	\
	if (replace) { \
		_regs._reg++; \
		ptrace(PTRACE_SETREGS, _cpid, NULL, &_regs); \
	} \
	output("%s(%s = %p - %s)", #_syscall, #_reg, (void *)(_regs._reg), tmp_buf); \
	if (replace) \
		output(" replaced with '%s' = ", tmp_buf + 1); \
	else \
		output("\n"); \
	catch_return(_cpid); \
	errno = 0; \
	ptrace_getregs(_cpid, _regs); \
	if (replace) { \
		_regs._reg--; \
	} \
	output(" = %llu\n", _regs.rax); \
	free(tmp_buf); \
})

//	ptrace(PTRACE_GETREGS, _cpid, NULL, &_regs); \




#include "ptrace_defs.h"


char *read_string(pid_t child, unsigned long addr) {
    char *val = malloc(4096);
    int allocated = 4096;
    int read = 0;
    unsigned long tmp;
    while (1) {
        if (read + sizeof tmp > allocated) {
            allocated *= 2;
            val = realloc(val, allocated);
        }
//        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
	tmp = ptrace(PTRACE_PEEKDATA, child, addr + read, 0);
        if(errno != 0) {
            val[read] = 0;
            break;
        }
        memcpy(val + read, &tmp, sizeof tmp);
        if (memchr(&tmp, 0, sizeof tmp) != NULL)
            break;
        read += sizeof tmp;
    }
    return val;
}
int read_int(pid_t child, unsigned long addr) {
	unsigned long tmp;

	errno = 0;
	tmp = ptrace(PTRACE_PEEKDATA, child, addr, 0);
	if (tmp == (unsigned long)(-1) && errno != 0)
		return 0;
	return (int)tmp;
}
int write_int(pid_t child, unsigned long long addr, int val) {
	unsigned long tmp;

//	errno = 0;
//	tmp = ptrace(PTRACE_PEEKDATA, child, addr, 0);

//	tmp &= ~0xffffffff;
//	tmp |= (unsigned long)(unsigned int)val;
	tmp = (unsigned long)(unsigned int)val;

output("setting value at %llx to %d\n", addr, val);

	errno = 0;
	if ((ptrace(PTRACE_POKEDATA, child, addr, val)) < 0) {
output("PTRACE_POKEDATA returned %d: %m\n", errno);

	}
	return val;
}

#ifndef CDROM_GET_CAPABILITY
#define CDROM_GET_CAPABILITY 0x5331
#endif
struct ioctl_names {
	unsigned long cmd;
	const char *name;
} ioctls[] = {
	{ BLKIOOPT, "BLKIOOPT" },
	{ BLKIOMIN, "BLKIOMIN" },
	{ BLKGETSIZE64, "BLKGETSIZE64" },
	{ BLKALIGNOFF, "BLKALIGNOFF" },
	{ BLKPBSZGET, "BLKPBSZGET" },
	{ BLKSSZGET, "BLKSSZGET" },
	{ BLKBSZSET, "BLKBSZSET" },
	{ BLKDISCARD, "BLKDISCARD" },
	{ BLKFLSBUF, "BLKFLSBUF" },
	{ CDROM_GET_CAPABILITY, "CDROM_GET_CAPABILITY" },
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

void trace_child(pid_t cpid) {
	struct user_regs_struct regs;
	int status;
	pid_t tmp_pid;
//	unsigned long var;

	config.parent = getpid();
	config.child = cpid;

output("tracer pid %d, child pid %d\n", config.parent, config.child);

	ptrace(PTRACE_ATTACH, cpid, NULL, NULL);
	ptrace(PTRACE_SETOPTIONS, cpid, 0, PTRACE_O_EXITKILL);
	ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);

	while (1) {
		if (config.child_exited)
			break;
		waitpid(cpid, &status, 0);
		if (WIFEXITED(status)) {
output("child process exited with %d?\n", WEXITSTATUS(status));
			break;
		} else if (WIFSIGNALED(status)) {
output("signaled\n");
break;
		} else if (WIFSTOPPED(status)) {
int stop_sig = WSTOPSIG(status);
if (stop_sig != 5) { /* SIGTRAP */
	output("stopped with %d\n", stop_sig);
	if (stop_sig == SIGSEGV) {
		output("exiting with SEGV\n");
		break;
	} else if (stop_sig == SIGABRT) {
		output("exiting with SIGABRT\n");
		break;
	}
}

		}

		errno = 0;
		if (ptrace(PTRACE_GETREGS, cpid, NULL, &regs) == -1) {
			debug_output("error calling ptrace(GETREGS): %m\n");
			ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
			continue;
		}

//		ptrace(PTRACE_GETEVENTMSG, cpid, NULL, &var);
//		printf("relevant pid: %d\n", (pid_t)var);

		switch (regs.orig_rax) {
			case SYS_getuid:
			case SYS_geteuid:
			case SYS_getgid:
			case SYS_getegid:


				ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);


				output("get%s%sid() = %d (faking 0)\n",
					(regs.orig_rax == SYS_geteuid || regs.orig_rax == SYS_getegid) ? "e" : "",
					(regs.orig_rax == SYS_getuid || regs.orig_rax == SYS_geteuid) ? "u" : "g",
					(pid_t)RETURN_CODE(&regs));
//				output(" = %d", (pid_t)RETURN_CODE(&regs));

//				ptrace(PTRACE_SYSEMU, cpid, NULL, NULL);
				SET_RETURN_CODE(&regs, 0);

//				printf(" - faking 0\n");




				break;
/*
				output("get%sgid() - faking 0", regs.orig_rax == SYS_getegid ? "e" : "");

				ptrace(PTRACE_SYSEMU, cpid, NULL, NULL);
				SET_RETURN_CODE(&regs, 0);
				output(" = %d\n", (pid_t)RETURN_CODE(&regs));

				break;
*/
			case SYS_ioctl: {
				int fd = (int)ARG_0(&regs);
				unsigned long cmd = ARG_1(&regs);
				unsigned long long ret = ARG_2(&regs);

//				output("ioctl(%d, %lx (%s))", fd, cmd, ioctl_name(cmd));
//				ptrace_getregs(cpid, &regs);

//ret = ARG_2(&regs);

				ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
				ptrace_getregs(cpid, &regs);

if (ret != ARG_2(&regs)) {
	output("arg address changed? %llx -> %llx\n", ret, ARG_2(&regs));
}
//output("address may be %lx\n", ret);
//output("maybe maybe maybe %d?\n", read_int(cpid, ret));

if (cmd == BLKIOMIN || cmd == BLKIOOPT) {

output("ioctl(%d, %lx (%s)) = %d",
	fd, cmd, ioctl_name(cmd), read_int(cpid, ret));
//output(" = %d", read_int(cpid, ret));

if (cmd == BLKIOMIN) {
	write_int(cpid, ret, 524288);
	output(" - adjusted to 524288");
} else if (cmd == BLKIOOPT) {
	write_int(cpid, ret, 262144);
	output(" - adjusted to 262144");
}
}

//output("something has ret: %lx\n", ret);
//output("maybe maybe maybe %d?\n", *(int *)(long *)(&ret));

//output("ioctl return code = %d", (pid_t)RETURN_CODE(&regs));


//				} else {
//					ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);

//ptrace(PTRACE_GETREGS, cpid, NULL, &regs);
//ptrace_getregs(cpid, &regs);


//output("return code = %d", (pid_t)RETURN_CODE(&regs));

//				}
				output("\n");
				break;
			}


//			debug_report_syscall_case(ioctl);
//			debug_report_syscall_case(getuid);
//			debug_report_syscall_case(getgid);
//			debug_report_syscall_case(geteuid);
//			debug_report_syscall_case(getegid);


			case -1:

// test whether we're still alive


if ((tmp_pid = waitpid(cpid, &status, WNOHANG)) > 0) {
	if (tmp_pid == cpid) {
		output("child pid exited?\n");
	} else {
		output("waitpid() returned %d?\n", tmp_pid);
	}
}

//if (WIFEXITED(status))
//break;
//else if (WIFSIGNALED(status)) {


output("syscall %llu (rax: %llu)?\n", regs.orig_rax, regs.rax);
//		ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
catch_return(cpid);
//ptrace_getregs(cpid, regs);
ptrace_getregs(cpid, &regs);
output("return? = %d\n", (pid_t)RETURN_CODE(&regs));
ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);

break;
			default:
//output("syscall %llu\n", regs.orig_rax);
//				debug_output("unrecognized syscall: %llu; regs - "
//					"rdi: %llu, rsi: 0x%016llx, rdx: 0x%016llx, rcx: 0x%016llx\n",
//					regs.orig_rax, regs.rdi, regs.rsi, regs.rdx, regs.rcx);
//catch_return(cpid);
		ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
				break;
		}
//		ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
	}
output("broke out?\n");
	exit(EXIT_SUCCESS);
}

static void init(void) {
	pid_t cpid;

	if (config.initialized)
		return;
	while (config.initializing)
		nop();
	if (config.initialized)
		return;

	config.initializing = true;

	debug_output("initializing tracer\n");

	if ((cpid = fork()) > 0)
		trace_child(cpid);

//	raise(SIGSTOP);
	config.child_initialized = true;
	ptrace(PTRACE_TRACEME, NULL, NULL, NULL);

	config.initialized = true;
	config.initializing = false;
}

__attribute__((constructor)) static void init_hooks(void) {
	init();
}
