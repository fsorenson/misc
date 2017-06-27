#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <dlfcn.h>
#include "test9_lib.h"



int main(int argc, char *argv[]) {
	set_func_t set_func;
	get_func_t get_func;
	char *error;
	char *p;

	int i;
	int ret;

	printf("starting test9\n");


printf("test9_section_size = %lu\n", test9_section_size);
printf("test9_section_base = %p\n", test9_section_base);

printf("set_func_offset = %p\n", set_func_offset);

printf("__test9_start = %p\n", __test9_start);
//printf("__test9_end = %p\n", __test9_end);
printf("__test9_end = %p\n", (char *)&__test9_end);

	char *blob = mmap(0, (unsigned long)test9_section_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
printf("blob is %p\n", blob);
p = test9_section_base;
for (i = 0 ; i < 50 ; i++) {
	printf("%02x ", *p++);
}
printf("\n");

	memcpy(blob, test9_section_base, (unsigned long)test9_section_size);
printf(".\n");



	printf("test9_section_base = %p\n", test9_section_base);


	printf("  set_func_addr = %p\n", set_func_addr);
	printf("  get_func_addr = %p\n", get_func_addr);
	printf("  print_func_addr = %p\n", print_func_addr);


	printf("test9_section_end = %p\n", test9_section_end);
	printf("test9_section_size = %p\n", test9_section_size);


	set_func = (set_func_t)set_func_addr;
	get_func = (get_func_t)get_func_addr;

	unsigned long foo;

	set_func(200);
	foo = get_func();
	printf("foo = %lu\n", foo);

	set_func(123);
	foo = get_func();
	printf("foo = %lu\n", foo);

	set_func(999);
	foo = get_func();
	printf("foo = %lu\n", foo);



//	set_func_t set_func2 = (set_func_t)dlsym(handle, "set_var9_func");
	set_func_t set_func2 = (set_func_t)blob + (set_func_addr - test9_section_base);
	printf("base is %p, set_func_addr = %p, blob = %p, set_func2 = %p\n",
		test9_section_base, set_func_addr, blob, set_func2);
	get_func_t get_func2 = (get_func_t)blob + (get_func_addr - test9_section_base);
	printf("base is %p, get_func_addr = %p, blob = %p, get_func2 = %p\n",
		test9_section_base, get_func_addr, blob, get_func2);


	foo = get_func2();
	printf("foo = %lu\n", foo);

	set_func2(987);
	foo = get_func2();
	printf("foo = %lu\n", foo);

	set_func2(654);
	foo = get_func2();


	set_func2(321);
	printf("foo = %lu\n", foo);

	printf("func = %p, func2 = %p\n", set_func, set_func2);

	printf("foo1 = %lu, foo2 = %lu\n", get_func(), get_func2());

/*
	printf("running the program\n");
	set_var9_func(700);
	print_var9_func();
	set_var9_func(14);
	print_var9_func();
	set_var9_func(8);
	print_var9_func();
*/

//	unsigned long base_addr = (unsigned long)&__start_test9;
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
