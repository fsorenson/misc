#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include "test9_lib_abs.h"

unsigned long __set_var9_func(unsigned long *var_ptr, unsigned long val) {
	printf("in %s, setting val at %p to %lu\n", __func__, var_ptr, val);
	return *var_ptr = val;
}
unsigned long __get_var9_func(unsigned long *var_ptr) {
	printf("in %s, val at %p is %lu\n", __func__, var_ptr, *var_ptr);
	return *var_ptr;
}
void __print_var9_func(unsigned long *var_ptr) {
	printf("in %s, val at %p is %lu\n", __func__, var_ptr, *var_ptr);
}
