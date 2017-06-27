#ifndef __TEST10_LIB_H__
#define __TEST10_LIB_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



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


#define MAIN_SECTION test10

#define FUNC_SUBSECTION ""
#define VARS_SUBSECTION vars



#define FUNC_SECTION_ATTRIBS \
	__attribute__((section("test10,\"awx\"#"), used, aligned(8), noinline))
#define FUNC_SECTION_INLINE_ATTRIBS \
	__attribute__((section("test10,\"awx\"#"), used, aligned(8)))

//	__attribute__((section(__PASTE3(__STR(MAIN_SECTION), ".", __STR(FUNC_SUBSECTION))), used, aligned(8)))
#define VARS_SECTION_ATTRIBS \
	__attribute__((section("test10,\"awx\",@progbits#"), used, aligned(8), nocommon))

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
#define plt_func_addr(func) ({ uint64_t addr; __asm__("mov " __STR(func) "@PLT, %0;": "=r"(addr)); addr; })
#define got_func_addr(func) ({ uint64_t addr; __asm__("mov " __STR(func) "@GOT, %0;": "=r"(addr)); addr; })

#define OBJ_START_ADDR(obj) \
	({ uint64_t addr ; __asm__("mov __start_" __STR(obj) "@GOTPCREL(%%rip), %0;": "=r"(addr)); addr; })
//	({ __asm__(__PASTE3("mov __start", __STR(obj), "@GOTPCREL(%rip), %rax")); })
//	({ __asm__("mov __start"##__STR(obj)##"@GOTPCREL(%rip), %rax"); })
#define OBJ_START_ADDR_FUNC(obj) \
	static inline uint64_t OBJ_FUNC_ATTRIBS(obj) get_obj_##obj##_start(void) { \
		__asm__("mov __start"##__STR(obj)##"@GOTPCREL(%rip), %rax"); \
	}

typedef typeof(printf) printf_func_t;
typedef typeof(open) open_func_t;
typedef typeof(close) close_func_t;



//static inline char *FUNC_SECTION_INLINE_ATTRIBS get_object_start_addr(void) {
//	        __asm__ ("mov __start_test10@GOTPCREL(%rip),%rax");
//}
struct obj_struct {
	uint64_t magic;
};


struct test10_offsets_struct {
	char *base;
	char *this_obj_base;
	off_t this_obj_offset;
	char *var_addr;
	char *set_addr;
	char *get_addr;
	char *print_addr;
	char *foo_addr;
	char *end;

	off_t var_off;
	off_t set_off;
	off_t get_off;
	off_t print_off;
	off_t foo_off;

	size_t size;

	char *relocated_base;
	char *init_addr;
	off_t init_off;

	char *foo2_addr;
	off_t foo2_off;

	char *foo3_addr;
	off_t foo3_off;

	char *foo4_addr;
	off_t foo4_off;


	void *printf_addr;
};



typedef unsigned long (*set_func_t)(unsigned long);
typedef unsigned long (*get_func_t)(void);
typedef void (*print_func_t)(void);
typedef struct test10_offsets_struct (*init_func_t)(uint64_t base, uint64_t obj_base);


extern unsigned long __test10_start[0];
extern unsigned long __test10_end[0];
//extern int var10;
extern unsigned long set_var10_func(unsigned long val);
extern unsigned long get_var10_func(void);
extern void print_var10_func(void);
extern struct test10_offsets_struct fill_offsets(void);

extern char test10_section_base[0];

extern unsigned long set_func_offset[0];
extern char set_func_addr[0];
extern char get_func_addr[0];
extern char print_func_addr[0];

extern char test10_section_end[0];

extern unsigned long test10_section_size[0];

//__asm__("test10 PROVIDE(__start_test10, ALIGN(4096))");

		//      __asm__ ("mov __start_test10@GOTPCREL(%rip),%rax");
		//
extern char __start_test10[0];
extern char __stop_test10[0];

extern off_t get_var10_myfunc_addr(void);
extern off_t get_var10_foo2_addr(void);
extern off_t get_var10_foo3_addr(void);
extern off_t get_var10_foo4_addr(void);

void *set_printf_addr(void *addr);


extern void *printf_addr;

#endif
