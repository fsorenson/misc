#ifndef __TEST9_LIB_H__
#define __TEST9_LIB_H__

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>


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


#define MAIN_SECTION test9

#define FUNC_SUBSECTION funcs
#define VARS_SUBSECTION vars



#define FUNC_SECTION_ATTRIBS \
	__attribute__((section(__STR(MAIN_SECTION)), used, aligned(8), noinline))
//#define FUNC_SECTION_ATTRIBS \
//	__attribute__((section(__STR(MAIN_SECTION)  "."  __STR(FUNC_SUBSECTION)), used, aligned(8), noinline))
//	__attribute__((section(__PASTE3(__STR(MAIN_SECTION), ".", __STR(FUNC_SUBSECTION))), used, aligned(8)))


#define VARS_SECTION_ATTRIBS \
	__attribute__((section(__STR(MAIN_SECTION)), used, aligned(8)))

//#define VARS_SECTION_ATTRIBS \
//	__attribute__((section(__STR(MAIN_SECTION) "." __STR(VARS_SUBSECTION)), used, aligned(8)))
//	__attribute__((section(__STR(VARS_SECTION)), used, aligned(8)))

#define SECTION_START(_section)		__PASTE(__start_, _section)
#define SECTION_STOP(_section)		__PASTE(__stop_, _section)
#define SECTION_SIZE(_section)		__PASTE(__size_, _section)

#define FUNCTION_SECTION_START SECTION_START(FUNC_SECTION)
#define FUNCTION_SECTION_STOP SECTION_STOP(FUNC_SECTION)
#define FUNCTION_SECTION_SIZE SECTION_SIZE(FUNC_SECTION)

typedef unsigned long (*set_func_t)(unsigned long);
typedef unsigned long (*get_func_t)(void);
typedef void (*print_func_t)(void);


extern unsigned long __test9_start[];
extern unsigned long __test9_end[];
//extern int var9;
extern unsigned long set_var9_func(unsigned long val);
extern unsigned long get_var9_func(void);
extern void print_var9_func(void);

extern char VARS_SECTION_ATTRIBS test9_section_base[];

extern unsigned long set_func_offset[];
extern char set_func_addr[];
extern char get_func_addr[];
extern char print_func_addr[];

extern char test9_section_end[];

extern unsigned long VARS_SECTION_ATTRIBS test9_section_size[];

#endif
