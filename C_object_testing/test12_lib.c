#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include <stdarg.h>
#include <unistd.h>
#include <string.h>

#include "test12_lib.h"


#define LIBNAME test12

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

//
// _int, _exp, _var for internal, export, variable?
//

#define FUNC_SECTION_ATTRIBS \
        __attribute__((section("test12,\"awx\"#"), used, aligned(8), noinline))
#define FUNC_SECTION_EXPORT_ATTRIBS \
        __attribute__((section("test12,\"awx\"#"), used, aligned(8), noinline))
#define FUNC_SECTION_INLINE_ATTRIBS \
        __attribute__((section("test12,\"awx\"#"), used, aligned(8)))

#define VARS_SECTION_ATTRIBS \
        __attribute__((section("test12,\"awx\",@progbits#"), used, aligned(8), nocommon))

#define SECTION_START(_section)         __PASTE(__start_, _section)
#define SECTION_STOP(_section)          __PASTE(__stop_, _section)
#define SECTION_SIZE(_section)          __PASTE(__size_, _section)

//extern const unsigned char __DATA__
unsigned long set_var12_func(unsigned long val);
extern char SECTION_START(LIBNAME)[0];
extern char SECTION_STOP(LIBNAME)[0];
extern char SECTION_SIZE(LIBNAME);


//typedef struct obj_struct (*init_func_t)(void);


static struct obj_struct VARS_SECTION_ATTRIBS self;

unsigned long FUNC_SECTION_EXPORT_ATTRIBS set_var12_func(unsigned long val) {

	return self.var = val;
}
unsigned long FUNC_SECTION_EXPORT_ATTRIBS get_var12_func(void) {
	return self.var;
}

void FUNC_SECTION_EXPORT_ATTRIBS print_var12_func(void) {
	printf("%s: var12=%d\n", __func__, self.var);
}


void FUNC_SECTION_ATTRIBS __attribute__((constructor)) __init_test12(void) {
//	self.magic = (((uint64_t)htonl(0x434f424a)) << 32) + htonl(0x53454c46);
	self.magic = (((uint64_t)htonl(*(uint32_t *)(&"COBJ"))) << 32) + htonl(0x53454c46);
//				"COBJ"   "SELF"

	self.var = 42;

	self.set = set_var12_func;
	self.get = get_var12_func;
	self.print = print_var12_func;

	self.start = SECTION_START(LIBNAME);
	self.stop = SECTION_STOP(LIBNAME);
	self.size = SECTION_STOP(LIBNAME) - SECTION_START(LIBNAME);
}
