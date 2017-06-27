#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include "test6.h"

struct test6_offsets __attribute__((aligned(sizeof(struct test6_offsets)), used, section("test6.vars"))) offsets;
int __attribute__((aligned(8), used, section("test6.vars"))) var6;

int __attribute__((aligned(8), used, section("test6.funcs"))) set_var6_func(int val) {
	printf("in %s, func addr = %p, var6 addr = %p\n", __func__, &set_var6_func, &var6);
	var6 = val;
	return var6;
}
int __attribute((aligned(8), used, section("test6.funcs"))) get_var6_func() {
	return var6;
}
void __attribute((aligned(8), used, section("test6.funcs"))) print_var6_func() {
	struct test6_data *base = (void *)(&print_var6_func - offsets.print_var_func);


	printf("var6 = %d\n", var6);
}
struct test6_data *__attribute((aligned(8), used, section("test6.funcs"))) init() {
	char *blob;
	unsigned long real_size = &__stop_test6 - &__start_test6;
//	struct test6_offsets *tmp_offsets;
	struct test6_data *this_obj;

	/* calculate some offsets */
	offsets.offsets = blob;
	offsets.var = ((void *)&var6 - (void *)&__start_test6);
	offsets.set_var_func = ((void *)&set_var6_func - (void *)&__start_test6);
	offsets.get_var_func = ((void *)&get_var6_func - (void *)&__start_test6);
	offsets.print_var_func = ((void *)&print_var6_func - (void *)&__start_test6);

	blob = mmap(0, real_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
	memcpy(blob, &__start_test6, real_size);

	this_obj = (struct test6_data *)blob;
	this_obj->set_var = (set_var_func_t)(this_obj + offsets.set_var_func);
	this_obj->get_var = (get_var_func_t)(this_obj + offsets.get_var_func);
	this_obj->print_var = (print_var_func_t)(this_obj + offsets.print_var_func);

/*
unsigned long offsets;
unsigned long var;
unsigned long data_end;

unsigned long func_start;
unsigned long set_var_func;
unsigned long get_var_func;
unsigned long print_var_func;
unsigned long func_end;
*/






	return this_obj;
}
extern char __start_test6;
extern char __stop_test6;
extern unsigned long test6_size;



