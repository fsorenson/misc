#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "test11_lib.h"


//unsigned long __attribute__((used)) __test11_start[0];
struct obj_struct VARS_SECTION_ATTRIBS self;

unsigned long FUNC_SECTION_ATTRIBS whizzer(unsigned long val) {
	return val*10;
}

unsigned long FUNC_SECTION_ATTRIBS set_var11_func(unsigned long val) {

	return self.var = val;
}
unsigned long FUNC_SECTION_ATTRIBS get_var11_func(void) {
	return self.var;
}

void FUNC_SECTION_ATTRIBS print_var11_func(void) {
	printf("%s: var11=%d\n", __func__, self.var);
}

/*
uint64_t FUNC_SECTION_ATTRIBS get_printf_addr(void) {
	__asm__("mov printf@GOT,%rax");
}
uint64_t FUNC_SECTION_ATTRIBS get_close_addr(void) {
	return (uint64_t)&close;
}
*/

#if 0
//#define fixup_func_addr(sym, offset) do { self.trampolines.sym += offset; } while (0)
struct test11_offsets_struct *FUNC_SECTION_ATTRIBS __init_test11_obj(void *base, void *obj_base) { /* original and new bases */
//	self = (typeof(self))obj_base;
	self.base = base;
//	self.this_obj_base = obj_base;

//	uint64_t obj_offset = obj_base - base;
//	self.this_obj_offset = obj_offset;
//	self.trampolines = &trampolines;
/*
	fixup_func_addr(clock_gettime, obj_offset);
	fixup_func_addr(exit, obj_offset);
	fixup_func_addr(sigemptyset, obj_offset);
	fixup_func_addr(sigaction, obj_offset);
*/

}
#endif


#if 0
#define dy_load_sym(sym) do { \
	char *error = NULL; \
	dlerror(); \
	trampolines.sym = (typedefof(sym) *)dlsym(self.libc_handle, __STR(sym)); \
	if ((error = dlerror()) != NULL) { \
		/* uh oh...  what now? */ \
	} \
} while (0)
#define load_sym(sym) self.trampolines.sym = (typedefof(sym) *)&sym
#endif



//init_func_t
void FUNC_SECTION_ATTRIBS __attribute__((constructor)) __init_test11(void) {
//	self.magic = (((uint64_t)htonl(0x434f424a)) << 32) + htonl(0x53454c46);
	self.magic = (((uint64_t)htonl(*(uint32_t *)(&"COBJ"))) << 32) + htonl(0x53454c46);
//				"COBJ"   "SELF"
#if 0
	self.libc_handle = dlopen("libc.so.6", RTLD_LAZY);
	if (self.libc_handle) {

		char *error = NULL;
		dlerror();
		load_sym(asprintf);
		load_sym(dprintf);
		load_sym(exit);
	}
#endif

	self.var = 42;

	self.set = set_var11_func;
	self.get = get_var11_func;
	self.print = print_var11_func;

	self.base = __start_test11;
	self.end = __stop_test11;
	self.size = __stop_test11 - __start_test11;

	self.init = (init_func_t)__init_test11;

//	char buf[10];
//	strncpy(buf, (char **)&self.magic, 8);
//	buf[8] = '\0';
//	printf("magic: %s\n", buf);


//	printf("whizzer(5) = %lu\n", whizzer(5));


}
