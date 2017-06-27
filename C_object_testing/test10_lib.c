#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include "test10_lib.h"



//struct test5_offsets __attribute__((aligned(sizeof(struct test6_offsets)), used, section("test6.vars"))) offsets;



static unsigned long __attribute__((used)) VARS_SECTION_ATTRIBS var10;
static struct test10_offsets_struct VARS_SECTION_ATTRIBS obj_offsets;


//char __attribute__((used)) test10_section_base[0];

unsigned long __attribute__((used)) __test10_start[0];
unsigned long __attribute__((used)) __test10_end[0];



char __attribute__((used)) set_func_addr[0];
unsigned long __attribute__((used)) set_func_offset[0];
char __attribute__((used)) get_func_addr[0];
char __attribute__((used)) print_func_addr[0];
char __attribute__((used)) test10_section_end[0];
char get_myfunc_addr[0];

unsigned long FUNC_SECTION_ATTRIBS set_var10_func(unsigned long val) {
//	printf("in %s, func_addr = %p, var10 addr = %p, var10 = %lu\n",
//		__func__, &set_var10_func, &var10, var10);
//	var10 = val;
//	return var10;
//	return __set_var10_func(&var10, val);
	return var10 = val;
}
unsigned long FUNC_SECTION_ATTRIBS get_var10_func(void) {
//	printf("in %s, func_addr = %p, var10 addr = %p, var10 = %lu\n",
//		__func__, &get_var10_func, &var10, var10);
//	return var10;
//	return __get_var10_func(&var10);
	return var10;
}

static uint64_t __attribute__((noinline)) _print_var10_func(char *func_addr) {

	typedef int (*printf_func_t)(const char *format, ...);
//typedef unsigned long (*set_func_t)(unsigned long);

	static char *msg VARS_SECTION_ATTRIBS  = "test printf from within _print_var10_func\n";

	printf_func_t f;
	f = (printf_func_t)plt_func_addr(printf);
//	f(msg);
	return (uint64_t)f;

//	printf("this_func_addr: %p\n", func_addr);
	printf(msg);
//	printf("this_func_addr is probably: %p\n", offsets.print_addr);
}
void FUNC_SECTION_ATTRIBS print_var10_func(void) {
	char __attribute__((aligned(1))) ary[] = { 'H', 'E', 'L', 'L', 'O', ' ', 'W', 'O', 'R', 'L', 'D', '!', '\n', '\0' };
	static char *msg VARS_SECTION_ATTRIBS  = "test printf from within _print_var10_func\n";
//this_func_addr:
//	unsigned long my_offset = (unsigned long)&print_var10_func - __start_test10;
//	unsigned long my_offset = &__print_var10_func_offset;

//	printf("in %s, func_addr = %p, var10 addr = %p, var10 = %lu\n",
//		__func__, &print_var10_func, &var10, var10);
//	__print_var10_func(&var10);

//	printf("my current base: %p\n", __start_test10);
//	_print_var10_func(&&this_func_addr);

#if 0
	typedef int (*printf_func_t)(const char *format, ...);
	printf_func_t f;
//	f = (printf_func_t)plt_addr(printf);
	f = obj_offsets.printf_addr;


//	f(ary);
#else
	printf_func_t *f;
//	f = (printf_func_t *)rip_rel_addr(printf);
	f = (printf_func_t *)obj_offsets.printf_addr;
//	f = (printf_func_t *)(obj_offsets.this_obj_offset + obj_offsets.print_off);
	f(ary);
	f("in print_var10_func, with base addr=%p (or maybe %p)\n", __start_test10, obj_offsets.this_obj_base);
//	printf(ary);
#endif

}
static inline char *FUNC_SECTION_INLINE_ATTRIBS get_object_start_addr(void) {
	return (char *)OBJ_START_ADDR(test10);
//	__asm__ ("mov __start_test10@GOTPCREL(%rip),%rax");
}
off_t FUNC_SECTION_ATTRIBS get_var10_myfunc_addr(void) {
//	off_t off = (char *)&get_var10_myfunc_addr - __start_test10;

	char *ref = get_object_start_addr();
	return (off_t)ref;

//	return (char *)&get_var10_myfunc_addr - __start_test10;
//	return (off_t)(char *)__start_test10;
}

static inline uint64_t FUNC_SECTION_INLINE_ATTRIBS get_foo2_addr(void) {
	uint64_t ip;
	__asm__ ("leaq (%%rip), %0;": "=r"(ip));
	return ip;
}
off_t FUNC_SECTION_ATTRIBS get_var10_foo2_addr(void) {
//	uint64_t ref = get_foo2_addr();
//	return (off_t)ref;
//	return (off_t)get_rip();
	return (off_t)rip_rel_addr(printf);
}
off_t FUNC_SECTION_ATTRIBS get_var10_foo3_addr(void) {
//	uint64_t ref = get_foo2_addr();
//	return (off_t)ref;
	return (off_t)obj_offsets.printf_addr;
}
off_t FUNC_SECTION_ATTRIBS get_var10_foo4_addr(void) {
	return (off_t)plt_func_addr(printf);
//	return (off_t)got_func_addr(printf);
}




void * FUNC_SECTION_ATTRIBS set_printf_addr(void *addr) {
	return obj_offsets.printf_addr = addr;
}


unsigned char *FUNC_SECTION_ATTRIBS init_func(uint64_t orig_base, uint64_t my_base) {

	obj_offsets.relocated_base = (char *)my_base;
	obj_offsets.this_obj_base = obj_offsets.relocated_base;


	obj_offsets.this_obj_offset = my_base - orig_base;

	obj_offsets.printf_addr += obj_offsets.this_obj_offset;


}
struct test10_offsets_struct FUNC_SECTION_ATTRIBS fill_offsets(void) {
//	struct test10_offsets_struct offsets;
	char *base_addr;

	obj_offsets.base = base_addr = __start_test10;
	obj_offsets.this_obj_base = base_addr;

	obj_offsets.end = __stop_test10;
	obj_offsets.size = obj_offsets.end - base_addr;

	obj_offsets.init_addr = (char *)&init_func;
	obj_offsets.init_off = obj_offsets.init_addr - base_addr;

	obj_offsets.var_addr = (char *)&var10;
	obj_offsets.set_addr = (char *)&set_var10_func;
	obj_offsets.get_addr = (char *)&get_var10_func;
	obj_offsets.print_addr = (char *)&print_var10_func;

	obj_offsets.var_off = obj_offsets.var_addr - base_addr;
	obj_offsets.set_off = obj_offsets.set_addr - base_addr;
	obj_offsets.get_off = obj_offsets.get_addr - base_addr;
	obj_offsets.print_off = obj_offsets.print_addr - base_addr;

	obj_offsets.foo_addr = (char *)&get_var10_myfunc_addr;
	obj_offsets.foo_off = obj_offsets.foo_addr - base_addr;

	obj_offsets.foo2_addr = (char *)&get_var10_foo2_addr;
	obj_offsets.foo2_off = obj_offsets.foo2_addr - base_addr;

	obj_offsets.foo3_addr = (char *)&get_var10_foo3_addr;
	obj_offsets.foo3_off = obj_offsets.foo3_addr - base_addr;


	obj_offsets.init_addr = (char *)&init_func;
	obj_offsets.init_off = obj_offsets.init_addr - base_addr;

	return obj_offsets;
}


