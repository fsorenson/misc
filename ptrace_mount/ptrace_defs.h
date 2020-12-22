#ifndef __PTRACE_DEFS__
#define __PTRACE_DEFS__

//#include "sos_hooks.h"
#include "ptrace_mount.h"
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

#define ARGUMENT_32_64(_regs, _reg32, _reg64) (ISLINUX32((_regs)) ? (_regs)->_reg32 : (_regs)->_reg64)
#define SET_ARGUMENT_32_64(_regs, _val, _reg32, _reg64) do { \
	if (ISLINUX32(_regs)) { (_regs)->_reg32 = (typeof((_regs)->_reg32))(_val); } \
	else { (_regs)->_reg64 = (typeof((_regs)->_reg64))(_val); } \
} while (0)

#if 0
#define ARGUMENT_0(x)		(ISLINUX32(x) ? (x)->rbx : (x)->rdi)
#define ARGUMENT_1(x)		(ISLINUX32(x) ? (x)->rcx : (x)->rsi)
#define ARGUMENT_2(x)		(ISLINUX32(x) ? (x)->rdx : (x)->rdx)
#define ARGUMENT_3(x)		(ISLINUX32(x) ? (x)->rsi : (x)->rcx)
#define ARGUMENT_4(x)		(ISLINUX32(x) ? (x)->rdi : (x)->r8)
#define ARGUMENT_5(x)		(ISLINUX32(x) ? (x)->rbp : (x)->r9)
#define SET_ARGUMENT_0(x, v)	do { \
	if (ISLINUX32(x)) { (x)->rbx = (typeof((x)->rbx))(v); } \
	else { (x)->rdi = ((typeof((x)->rdi))(v)); } \
} while (0)
#define SET_ARGUMENT_1(x, v)	do { \
	if (ISLINUX32(x)) { (x)->rcx = ((typeof((x)->rcx))(v)); } \
	else { (x)->rsi = ((typeof((x)->rsi))(v)); } \
} while (0)
#define SET_ARGUMENT_1(x, v)	if (ISLINUX32(x)) (x)->rcx = (v); else (x)->rsi = (v)
#define SET_ARGUMENT_2(x, v)	if (ISLINUX32(x)) (x)->rdx = (v); else (x)->rdx = (v)
#define SET_ARGUMENT_3(x, v)	if (ISLINUX32(x)) (x)->rsi = (v); else (x)->rcx = (v)
#define SET_ARGUMENT_4(x, v)	if (ISLINUX32(x)) (x)->rdi = (v); else (x)->r8 = (v)
#define SET_ARGUMENT_5(x, v)	if (ISLINUX32(x)) (x)->rbp = (v); else (x)->r9 = (v)
#endif

#define ARGUMENT_0(_regs) ARGUMENT_32_64(_regs, rbx, rdi)
#define ARGUMENT_1(_regs) ARGUMENT_32_64(_regs, rcx, rsi)
#define ARGUMENT_2(_regs) ARGUMENT_32_64(_regs, rdx, rdx)
#define ARGUMENT_3(_regs) ARGUMENT_32_64(_regs, rsi, rcx)
#define ARGUMENT_4(_regs) ARGUMENT_32_64(_regs, rdi, r8)
#define ARGUMENT_5(_regs) ARGUMENT_32_64(_regs, rbp, r9)
#define SET_ARGUMENT_0(_regs, _val) SET_ARGUMENT_32_64(_regs, _val, rbx, rdi)
#define SET_ARGUMENT_1(_regs, _val) SET_ARGUMENT_32_64(_regs, _val, rcx, rsi)
#define SET_ARGUMENT_2(_regs, _val) SET_ARGUMENT_32_64(_regs, _val, rdx, rdx)
#define SET_ARGUMENT_3(_regs, _val) SET_ARGUMENT_32_64(_regs, _val, rsi, rcx)
#define SET_ARGUMENT_4(_regs, _val) SET_ARGUMENT_32_64(_regs, _val, rdi, r8)
#define SET_ARGUMENT_5(_regs, _val) SET_ARGUMENT_32_64(_regs, _val, rbp, r9)

#define ptrace_getregs(_cpid, _regs) do { ptrace(PTRACE_GETREGS, _cpid, NULL, _regs); } while (0)




#endif
