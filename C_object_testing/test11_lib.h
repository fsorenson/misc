#ifndef __TEST11_LIB_H__
#define __TEST11_LIB_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <libgen.h>
#include <time.h>
#include <signal.h>
#include <dlfcn.h>


#define offsetof(type, member)  __builtin_offsetof(type, member)


#pragma GCC diagnostic ignored "-Wvariadic-macros"
#define ___STR(x...)    #x
#define __STR(x...)     ___STR(x)
#define __XSTR(s)       __STR(s)
#pragma GCC diagnostic warning "-Wvariadic-macros"

#define ___PASTE(a,b)           a##b
#define ___PASTE3(a,b,c)        a##b##c
#define ___PASTE4(a,b,c,d)      a##b##c##d

#define __PASTE(a,b)            ___PASTE(a,b)
#define __PASTE3(a,b,c)         ___PASTE3(a,b,c)
#define __PASTE4(a,b,c,d)       ___PASTE4(a,b,c,d)


#define MAIN_SECTION test11

#define FUNC_SUBSECTION ""
#define VARS_SUBSECTION vars


#define FUNC_SECTION_ATTRIBS \
	__attribute__((section("test11,\"awx\"#"), used, aligned(8), noinline))
#define FUNC_SECTION_INLINE_ATTRIBS \
	__attribute__((section("test11,\"awx\"#"), used, aligned(8)))

//	__attribute__((section(__PASTE3(__STR(MAIN_SECTION), ".", __STR(FUNC_SUBSECTION))), used, aligned(8)))
#define VARS_SECTION_ATTRIBS \
	__attribute__((section("test11,\"awx\",@progbits#"), used, aligned(8), nocommon))

//	__attribute__((section(__PASTE(__STR(MAIN_SECTION),"#\n\r")), used, aligned(8), nocommon))
//	__attribute__((section(__STR(MAIN_SECTION) "." __STR(VARS_SUBSECTION)), used, aligned(8)))
//	__attribute__((section(__STR(VARS_SECTION)), used, aligned(8)))

#define SECTION_START(_section)		__PASTE(__start_, _section)
#define SECTION_STOP(_section)		__PASTE(__stop_, _section)
#define SECTION_SIZE(_section)		__PASTE(__size_, _section)

#define FUNCTION_SECTION_START SECTION_START(FUNC_SECTION)
#define FUNCTION_SECTION_STOP SECTION_STOP(FUNC_SECTION)
#define FUNCTION_SECTION_SIZE SECTION_SIZE(FUNC_SECTION)


#define get_rip() ({ uint64_t ip; __asm__("leaq (%%rip), %0;": "=r"(ip)); ip; })


#define OBJ_FUNC_ATTRIBS(obj) __attribute__((section(__PASTE(__STR(obj), ",\"awx\"#")), used, aligned(8), noinline))
#define OBJ_INLINE_FUNC_ATTRIBS(obj) __attribute__((section(__PASTE(__STR(obj), ""c_obj,\"awx\"#")), used, aligned(8)))
#define OBJ_VAR_ATTRIBS(obj) __attribute__((section(__PASTE(__STR(obj),"\"awx\",@progbits#")), used, aligned(8), nocommon))


#define rip_rel_addr(func) ({ uint64_t addr; __asm__("mov " __STR(func) "@GOTPCREL(%%rip), %0;": "=r"(addr)); addr; })
//#define plt_addr(func) ({ uint64_t addr; __asm__("mov " __STR(func) "@PLT(%%0);": "=r"(addr)); addr; })
#define plt_addr(func) ({ uint64_t addr; __asm__("mov " __STR(func) "@PLT, %0;": "=r"(addr)); addr; })

#define OBJ_START_ADDR(obj) \
	({ uint64_t addr ; __asm__("mov __start_" __STR(obj) "@GOTPCREL(%%rip), %0;": "=r"(addr)); addr; })
#define OBJ_START_ADDR_FUNC(obj) \
	static inline uint64_t OBJ_FUNC_ATTRIBS(obj) get_obj_##obj##_start(void) { \
		__asm__("mov __start"##__STR(obj)##"@GOTPCREL(%rip), %rax"); \
	}


/* predeclare structs */
struct obj_struct;

typedef unsigned long (*set_func_t)(unsigned long);
typedef unsigned long (*get_func_t)(void);
typedef void (*print_func_t)(void);
typedef struct obj_struct (*init_func_t)(void);

typedef uint64_t (*get_addr_t)(void);


//extern const unsigned char __DATA__
unsigned long set_var11_func(unsigned long val);
extern char __start_test11[0];
extern char __stop_test11[0];



#if 0
#define typedefof(func) __PASTE(func,_func_t)
#define typedef_func_sym(func) typedef typeof(func) typedefof(func)

#define tramp_func_sym(func) typedefof(func) *func

typedef_func_sym(asprintf);
typedef_func_sym(dprintf);
typedef_func_sym(fprintf);

typedef_func_sym(sigemptyset);
typedef_func_sym(sigaction);
#endif
#if 0
struct trampoline_struct {
	tramp_func_sym(asprintf);
	tramp_func_sym(dprintf);
	tramp_func_sym(fprintf);
	tramp_func_sym(printf);

	tramp_func_sym(exit);

	tramp_func_sym(sigemptyset);
	tramp_func_sym(sigaction);
};
#endif
struct obj_struct {
	uint64_t magic;

	uint64_t var;

	set_func_t set;
	get_func_t get;
	print_func_t print;

	void *base;
	void *end;
	size_t size;
	Lmid_t ns; //lm_list; /* link map list */

	init_func_t init;
//	char func1[(char *)&set_var11_func - (char *)__start_test11];
	char blob[];
};
//extern struct obj_struct self;

#endif
