#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include "test9_lib.h"
#include "test9_lib_abs.h"


//struct test5_offsets __attribute__((aligned(sizeof(struct test6_offsets)), used, section("test6.vars"))) offsets;
static unsigned long VARS_SECTION_ATTRIBS var9;

static unsigned long VARS_SECTION_ATTRIBS __attributefoobarbaz;

unsigned long VARS_SECTION_ATTRIBS test9_section_size[];

char VARS_SECTION_ATTRIBS test9_section_base[];

unsigned long VARS_SECTION_ATTRIBS __test9_start[];
unsigned long VARS_SECTION_ATTRIBS __test9_end[];



char VARS_SECTION_ATTRIBS set_func_addr[];
unsigned long VARS_SECTION_ATTRIBS set_func_offset[];
char VARS_SECTION_ATTRIBS get_func_addr[];
char VARS_SECTION_ATTRIBS print_func_addr[];
char VARS_SECTION_ATTRIBS test9_section_end[];

unsigned long FUNC_SECTION_ATTRIBS set_var9_func(unsigned long val) {
//	printf("in %s, func_addr = %p, var9 addr = %p, var9 = %lu\n",
//		__func__, &set_var9_func, &var9, var9);
//	var9 = val;
//	return var9;
	return __set_var9_func(&var9, val);
}
unsigned long FUNC_SECTION_ATTRIBS get_var9_func(void) {
//	printf("in %s, func_addr = %p, var9 addr = %p, var9 = %lu\n",
//		__func__, &get_var9_func, &var9, var9);
//	return var9;
	return __get_var9_func(&var9);
}
void FUNC_SECTION_ATTRIBS print_var9_func(void) {
//	unsigned long my_offset = (unsigned long)&print_var9_func - __start_test9;
//	unsigned long my_offset = &__print_var9_func_offset;

//	printf("in %s, func_addr = %p, var9 addr = %p, var9 = %lu\n",
//		__func__, &print_var9_func, &var9, var9);
	__print_var9_func(&var9);


//	printf("var9 = %lu\n", var9);
}

