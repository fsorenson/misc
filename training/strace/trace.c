#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/uio.h>


#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#include "x64_syscalls.h"

/*
  __extension__ unsigned long long int r15;
  __extension__ unsigned long long int r14;
  __extension__ unsigned long long int r13;
  __extension__ unsigned long long int r12;
  __extension__ unsigned long long int rbp;
  __extension__ unsigned long long int rbx;
  __extension__ unsigned long long int r11;
  __extension__ unsigned long long int r10;
  __extension__ unsigned long long int r9;
  __extension__ unsigned long long int r8;
  __extension__ unsigned long long int rax;
  __extension__ unsigned long long int rcx;
  __extension__ unsigned long long int rdx;
  __extension__ unsigned long long int rsi;
  __extension__ unsigned long long int rdi;
  __extension__ unsigned long long int orig_rax;
  __extension__ unsigned long long int rip;
  __extension__ unsigned long long int cs;
  __extension__ unsigned long long int eflags;
  __extension__ unsigned long long int rsp;
  __extension__ unsigned long long int ss;
  __extension__ unsigned long long int fs_base;
  __extension__ unsigned long long int gs_base;
  __extension__ unsigned long long int ds;
  __extension__ unsigned long long int es;
  __extension__ unsigned long long int fs;
  __extension__ unsigned long long int gs;
*/
#define PRINT_REG(_regs, _reg) do { \
	printf("%s:\t0x%016llx\n", #_reg, _regs._reg); \
} while (0)
void dump_regs(struct user_regs_struct regs) {
	PRINT_REG(regs, rax);
	PRINT_REG(regs, orig_rax);
	PRINT_REG(regs, rcx);
	PRINT_REG(regs, rdx);
	PRINT_REG(regs, rsi);
	PRINT_REG(regs, rdi);
	PRINT_REG(regs, r15);
	PRINT_REG(regs, r14);
	PRINT_REG(regs, r13);
	PRINT_REG(regs, r12);
	PRINT_REG(regs, rbp);
	PRINT_REG(regs, rbx);
	PRINT_REG(regs, r11);
	PRINT_REG(regs, r10);
	PRINT_REG(regs, r9);
	PRINT_REG(regs, r8);
}
#define PRINT_REGS(_regs1, _regs2, _reg) do { \
	printf("%s %8s 0x%016llx   0x%016llx\n", \
		_regs1._reg == _regs2._reg ? " " : "*", \
		#_reg, _regs1._reg, _regs2._reg); \
} while (0)
void print_regsdiff(struct user_regs_struct regs1, struct user_regs_struct regs2) {
	PRINT_REGS(regs1, regs2, rip);
	PRINT_REGS(regs1, regs2, rax);
	PRINT_REGS(regs1, regs2, orig_rax);

	PRINT_REGS(regs1, regs2, rdi);
	PRINT_REGS(regs1, regs2, rsi);
	PRINT_REGS(regs1, regs2, rdx);
	PRINT_REGS(regs1, regs2, rcx);
	PRINT_REGS(regs1, regs2, r8);
	PRINT_REGS(regs1, regs2, r9);

	PRINT_REGS(regs1, regs2, r15);
	PRINT_REGS(regs1, regs2, r14);
	PRINT_REGS(regs1, regs2, r13);
	PRINT_REGS(regs1, regs2, r12);
	PRINT_REGS(regs1, regs2, rbp);
	PRINT_REGS(regs1, regs2, rbx);
	PRINT_REGS(regs1, regs2, r11);
	PRINT_REGS(regs1, regs2, r10);
}
#define GET_REGS0(_pid, _regs) ({ ptrace(PTRACE_GETREGS, _pid, NULL, &_regs); })
#define GET_REGS(_pid, _regs) ({ \
	struct iovec iov = { .iov_base = &_regs, .iov_len = sizeof(_regs) }; \
	ptrace(PTRACE_GETREGSET, _pid, NT_PRSTATUS, &iov); \
	})

void trace_process(pid_t traced_pid) {
	struct user_regs_struct regs;
	struct user_regs_struct regs1, regs2;
	struct iovec iov;
	int status;

        ptrace(PTRACE_ATTACH, traced_pid, NULL, NULL);
        ptrace(PTRACE_SETOPTIONS, traced_pid, NULL, PTRACE_O_EXITKILL);
        ptrace(PTRACE_SETOPTIONS, traced_pid, NULL, PTRACE_O_TRACESYSGOOD);
        ptrace(PTRACE_SYSCALL, traced_pid, NULL, NULL);


	// need to catch a syscall-exit-stop to begin with, then restart
	waitpid(traced_pid, &status, 0);
	if (WIFEXITED(status)) // traced process exited
		return;
	ptrace(PTRACE_SYSCALL, traced_pid, NULL, NULL);


        while (1) {
		waitpid(traced_pid, &status, 0);
//		wait4(traced_pid, &status, WNOHANG|__WALL, NULL);
//		wait4(traced_pid, &status, , NULL);
                if (WIFEXITED(status)) // traced process exited
                        break;


		if ((GET_REGS(traced_pid, regs)) == -1) {
//		if ((ptrace(PTRACE_GETREGS, traced_pid, NULL, &regs)) == -1) {
			printf("error calling ptrace(GETREGS): %m\n");
			ptrace(PTRACE_SYSCALL, traced_pid, NULL, NULL);
			continue;
		}
                printf("got a syscall: %d (%s) (status %x)\n", (int)regs.orig_rax, get_syscall_name_x86_64((int)regs.orig_rax), status);
		GET_REGS(traced_pid, regs1);
//ptrace(PTRACE_GETREGS, traced_pid, NULL, &regs1);
		dump_regs(regs);


                ptrace(PTRACE_SYSCALL, traced_pid, NULL, NULL);
                waitpid(traced_pid, &status, 0);
                if (WIFEXITED(status)) // traced process exited
                        break;

ptrace(PTRACE_GETREGS, traced_pid, NULL, &regs);
                printf("returned from a syscall: %s (status: %x)\n", get_syscall_name_x86_64((int)regs.orig_rax), status);
ptrace(PTRACE_GETREGS, traced_pid, NULL, &regs2);

print_regsdiff(regs1, regs2);

printf("\n");

                ptrace(PTRACE_SYSCALL, traced_pid, NULL, NULL);
        }
}


int main(int argc, char *argv[]) {
	pid_t traced_pid;


#if 0
	int i;
	for (i = 0 ; i < ARRAY_SIZE(x86_64_syscalls) ; i++) {
		printf("syscall %d = %s\n", i, get_syscall_name_x86_64(i));
	}
	printf("size: %lu\n", sizeof (struct user_regs_struct));
#endif

	if (argc != 2) {
		printf("usage: %s <pid>\n", argv[0]);
		return EXIT_FAILURE;
	}
	traced_pid = strtol(argv[1], NULL, 10);
	if (traced_pid < 2) {
		printf("unable to trace pid %d\n", traced_pid);
		return EXIT_FAILURE;
	}

	trace_process(traced_pid);

	return EXIT_SUCCESS;
}

