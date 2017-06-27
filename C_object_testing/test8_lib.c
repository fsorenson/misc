#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include "test8_lib.h"


char __start_test8;
char __start_test8_abs;

//struct test6_offsets __attribute__((aligned(sizeof(struct test6_offsets)), used, section("test6.vars"))) offsets;
static int VARS_SECTION_ATTRIBS var8;

int FUNC_SECTION_ATTRIBS set_var8_func(int val) {
	printf("in %s, func_addr = %p, var8 addr = %p, var8 = %d\n",
		__func__, &set_var8_func, &var8, var8);
	var8 = val;
	return var8;
}
int FUNC_SECTION_ATTRIBS get_var8_func(void) {
	printf("in %s, func_addr = %p, var8 addr = %p, var8 = %d\n",
		__func__, &get_var8_func, &var8, var8);
	return var8;
}
void FUNC_SECTION_ATTRIBS print_var8_func(void) {
//	unsigned long my_offset = (unsigned long)&print_var8_func - __start_test8;
//	unsigned long my_offset = &__print_var8_func_offset;

	printf("in %s, func_addr = %p, var8 addr = %p, var8 = %d\n",
		__func__, &print_var8_func, &var8, var8);
//	printf("**** offset to this function: %lx\n", my_offset);

//	struct test6_data *base = (void *)(&print_var6_func - offsets.print_var_func);


	printf("var8 = %d\n", var8);
}

