#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <execinfo.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <string.h>
#include <limits.h>
#include <syscall.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <errno.h>

//#include "sos_hooks.h"
#include "ptrace_mount.h"
#include "fake_calls.h"


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


//#define replace_this_path(_path) (!strncmp(_path, "/proc", 5) || !strncmp(_path, "/etc", 4))

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


#define debug_report_syscall(_syscall) do { \
	debug_output("syscall: %s (%d)\n", #_syscall, PASTE(SYS_, _syscall)); \
} while (0)

#define debug_report_syscall_case(_syscall) \
	case PASTE(SYS_, _syscall): \
		debug_report_syscall(_syscall); \
		catch_return(cpid); \
		break;


#define output_syscall_hit(_cpid, _syscall, _regs, _reg) ({ \
	char *tmp_buf = read_string(_cpid, _regs._reg); \
	\
	output("%s(%s = %p - %s)\n", #_syscall, #_reg, (void *)(_regs._reg), tmp_buf); \
	catch_return(_cpid); \
	ptrace(PTRACE_GETREGS, _cpid, NULL, &_regs); \
	output(" = %llu\n", _regs.rax); \
	free(tmp_buf); \
})


int fake_calls_init(void);

int fake_mount(const char *source, const char *target,
	const char *filesystemtype, unsigned long mountflags,
	const void *data);



struct config config = {
	.initializing = false,
	.initialized = false,
	.child_exited = false
};

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
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
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

void trace_child(pid_t cpid) {
	struct user_regs_struct regs;
	int status;

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
		if (WIFEXITED(status))
			break;
		if (ptrace(PTRACE_GETREGS, cpid, NULL, &regs) == -1) {
			debug_output("error calling ptrace(GETREGS): %m\n");
			ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
			continue;
		}

		switch (regs.orig_rax) {
			case SYS_mount:
				output("hit sys_mount\n");
				output_syscall_hit(cpid, mount, regs, rdi);
				break;
			case SYS_open:
//				fake_syscall_open(cpid, &regs);
				output_syscall_hit(cpid, open, regs, rdi);
//				catch_return(cpid);
//				try_replace_path(cpid, open, regs, rdi); break;
				break;
			case SYS_lstat:
//				fake_syscall_lstat(cpid, &regs);
				output_syscall_hit(cpid, lstat, regs, rdi);
//				catch_return(cpid);
				break;
			debug_report_syscall_case(lseek);
			debug_report_syscall_case(socket);
			debug_report_syscall_case(connect);

			case -1:
output("syscall %llu (rax: %llu)?\n", regs.orig_rax, regs.rax);
catch_return(cpid);
ptrace_getregs(cpid, regs);
trace_syscall("return? = %d\n", (pid_t)RETURN_CODE(&regs));
break;
			default:
				debug_output("unrecognized syscall: %llu; regs - "
					"rdi: %llu, rsi: 0x%016llx, rdx: 0x%016llx, rcx: 0x%016llx\n",
					regs.orig_rax, regs.rdi, regs.rsi, regs.rdx, regs.rcx);
catch_return(cpid);
				break;
		}
		ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
	}
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

	fake_calls_init();


	if ((cpid = fork()) > 0)
		trace_child(cpid);

	raise(SIGSTOP);

	config.initialized = true;
	config.initializing = false;
}

__attribute__((constructor)) static void init_hooks(void) {
	init();
}

