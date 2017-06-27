#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <dlfcn.h>
#include "test8_lib.h"



int main(int argc, char *argv[]) {
	void *handle;
	set_func_t set_func;
	char *error;

	int i;
	int ret;

/*
	handle = dlopen("./libtest8.so", RTLD_NOW|RTLD_LOCAL|RTLD_DEEPBIND);
	if (!handle) {
		printf("error opening dynamic lib: %s\n", dlerror());
		return EXIT_FAILURE;
	}
	dlerror();
*/

/*
//	set_func = *(set_func_t *) dlsym
	set_func = (set_func_t) dlsym(handle, "set_var8_func");

	error = dlerror();
	if (error != NULL) {
		printf("error dlsym(\"set_var8_func\": %s\n", error);
		return EXIT_FAILURE;
	}
*/

	set_func = set_var8_func;

	
	printf("start_test8 = %p, start_test8_2 = %p\n", __start_test8, __start_test8_abs);


	set_func(200);
	set_func(123);
	set_func(999);

//	set_func_t set_func2 = (set_func_t)dlsym(handle, "set_var8_func");
	set_func_t set_func2 = set_func;
	set_func2(987);
	set_func2(654);
	set_func2(321);


	printf("func = %p, func2 = %p\n", set_func, set_func2);


/*
	printf("running the program\n");
	set_var8_func(700);
	print_var8_func();
	set_var8_func(14);
	print_var8_func();
	set_var8_func(8);
	print_var8_func();
*/

//	unsigned long base_addr = (unsigned long)&__start_test8;
//	printf("base addr = %p\n", base_addr);

/*
//	void *set_var7_func_offset = (void *)(&__set_var7_func_section_offset - &__start_test7);
//	void *get_var7_func_offset = (&__get_var7_func_section_offset - base_addr);
//	void *print_var7_func_offset = (&__print_var7_func_section_offset - base_addr);
	void *set_var7_func_offset = (void *)((char *)&set_var7_func - &__start_test7);
	printf("set_func_offset = %p\n", set_var7_func_offset);

	void *get_var7_func_offset = (void *)((char *)&get_var7_func - &__start_test7);
	printf("get_func_offset = %p\n", get_var7_func_offset);

	void *print_var7_func_offset = (void *)((char *)&print_var7_func - &__start_test7);
	printf("print_func_offset = %p\n", print_var7_func_offset);

	void *test7_section_size = (void *)(&__stop_test7 - &__start_test7);
	printf("__size_test7 = %lu\n", test7_section_size);
	printf("\n\n*****\n\n");
*/


#if 0
//	set_func_t sf = (set_func_t)(unsigned long)blob + (unsigned long)&set_var7_func - (unsigned long)&var7;
//	print_func_t pf = (print_func_t)(unsigned long)blob + (unsigned long)&print_var7_func - (unsigned long)&var7;
	set_func_t sf = (set_func_t)(unsigned long)(blob + (unsigned long)set_var7_func_offset);
	print_func_t pf = (print_func_t)(unsigned long)(blob + (unsigned long)print_var7_func_offset);

	printf("sf = %p\n", sf);
	printf("pf = %p\n", pf);

//printf("__print_var7_func_offset = %p\n", __print_var7_func_offset);

	sf(50);
	pf();


//		0x600088

//	fn_dup = (func1_t)blob;
#endif


	return EXIT_SUCCESS;
}
