#ifndef __PTRACE_DEFS__
#define __PTRACE_DEFS__

#include <sys/ptrace.h>

enum LINUX_CALL_TYPES {
	LINUX64 = 0,
	LINUX32 = 1,
	LINUX_NUM_VERSIONS = 2
};

#pragma GCC diagnostic ignored "-Wunused-function"
static enum LINUX_CALL_TYPES linux_call_type(long codesegment) {
	if (codesegment == 0x33)
		return (LINUX64);
	else if (codesegment == 0x23)
		return (LINUX32);
	else {
		output("%s:%d: unknown code segment %lx\n",
			__FILE__, __LINE__, codesegment);
		exit(EXIT_FAILURE);
	}
}
#pragma GCC diagnostic warning "-Wunused-function"

#define ISLINUX32(x)		(linux_call_type((x)->cs) == LINUX32)
#define SYSCALL_NUM(x)		(x)->orig_rax
#define RETURN_CODE(x)		(ISLINUX32(x) ? (long)(int)(x)->rax : (x)->rax)
#define SET_RETURN_CODE(x, v)	(x)->rax = (v)
#define STACK_PTR(x)		(x)->rsp
#define SET_STACK_PTR(x, v)	(x)->rsp = (v)

#define ARG_32_64(_regs, _reg32, _reg64) (ISLINUX32((_regs)) ? (_regs)->_reg32 : (_regs)->_reg64)
#define SET_ARG_32_64(_regs, _val, _reg32, _reg64) do { \
	if (ISLINUX32(_regs)) { (_regs)->_reg32 = (typeof((_regs)->_reg32))(_val); } \
	else { (_regs)->_reg64 = (typeof((_regs)->_reg64))(_val); } \
} while (0)

#define ARG_0(_regs) ARG_32_64(_regs, rbx, rdi)
#define ARG_1(_regs) ARG_32_64(_regs, rcx, rsi)
#define ARG_2(_regs) ARG_32_64(_regs, rdx, rdx)
#define ARG_3(_regs) ARG_32_64(_regs, rsi, rcx)
#define ARG_4(_regs) ARG_32_64(_regs, rdi, r8)
#define ARG_5(_regs) ARG_32_64(_regs, rbp, r9)
#define SET_ARG_0(_regs, _val) SET_ARG_32_64(_regs, _val, rbx, rdi)
#define SET_ARG_1(_regs, _val) SET_ARG_32_64(_regs, _val, rcx, rsi)
#define SET_ARG_2(_regs, _val) SET_ARG_32_64(_regs, _val, rdx, rdx)
#define SET_ARG_3(_regs, _val) SET_ARG_32_64(_regs, _val, rsi, rcx)
#define SET_ARG_4(_regs, _val) SET_ARG_32_64(_regs, _val, rdi, r8)
#define SET_ARG_5(_regs, _val) SET_ARG_32_64(_regs, _val, rbp, r9)

#define ptrace_getregs(_cpid, _regs) do { ptrace(PTRACE_GETREGS, _cpid, NULL, _regs); } while (0)
//#define ptrace_getregs(_cpid, _regs) do { ptrace(PTRACE_GETREGS, _cpid, _regs, NULL); } while (0)




#endif
