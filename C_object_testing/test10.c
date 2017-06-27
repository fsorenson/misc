#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include "test10_lib.h"


void *printf_addr;

int main(int argc, char *argv[]) {
	set_func_t set_func;
	get_func_t get_func;
	char *error;
	char *p;

	int i;
	int ret;
	struct test10_offsets_struct offsets;


	printf("starting test10\n");
	printf_addr = &printf;

	printf("address of printf is %p\n", printf_addr);


	offsets = fill_offsets();
	set_printf_addr(printf_addr);

unsigned long sectsize = __stop_test10 - __start_test10;
//printf("offsets.size = %lu\n", offsets.size);
printf("sectsize = %lu\n", sectsize);

printf("set_func_offset = %p\n", set_func_offset);

//printf("__test10_start = %p\n", __test10_start);
//printf("__test10_end = %p\n", __test10_end);
//printf("__test10_end = %p\n", (char *)&__test10_end);
printf("__start_test10 = %p\n", __start_test10);
printf("__stop_test10 = %p\n", __stop_test10);
printf("set_var10_func = %p\n", &set_var10_func);


	char *blob = mmap(0, sectsize, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
printf("blob is %p\n", blob);
p = offsets.base;
for (i = 0 ; i < 50 ; i++) {
	printf("%02x ", *p++);
}
printf("\n");

	memcpy(blob, offsets.base, offsets.size);
printf(".\n");
	init_func_t obj_init = (init_func_t)(blob + offsets.init_off);
	obj_init((uint64_t)offsets.base, (uint64_t)blob);

	printf("offsets.size = %p\n", offsets.size);


	printf("  set_var10_func = %p\n", set_var10_func);
	printf("  get_var10_func = %p\n", get_var10_func);
	printf("  print_func_addr = %p\n", print_func_addr);


	printf("test10_section_end = %p\n", test10_section_end);
	printf("offsets.size = %p\n", offsets.size);


	set_func = (set_func_t)set_var10_func;
	get_func = (get_func_t)get_var10_func;

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



//	set_func_t set_func2 = (set_func_t)dlsym(handle, "set_var10_func");
	set_func_t set_func2 = (set_func_t)(blob + offsets.set_off);
	printf("base is %p, set_func_addr = %p, blob = %p, set_func2 = %p\n",
		offsets.base, set_func_addr, blob, set_func2);
	get_func_t get_func2 = (get_func_t)(blob + offsets.get_off);
	printf("base is %p, get_var10_func = %p, blob = %p, get_func2 = %p\n",
		offsets.base, get_var10_func, blob, get_func2);

	print_func_t print_func = (print_func_t)offsets.print_addr;
	print_func_t print_func2 = (print_func_t)(blob + offsets.print_off);

	print_func();
//	printf("about to call second print function\n");
//	print_func2();


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

	printf("*** foo1 = %lu, foo2 = %lu\n", get_func(), get_func2());


	printf("\n");
	printf("print functions:\n");


	typedef unsigned long (*foo_func_t)(void);

//printf("1: ");
	print_func();
//printf("2: "); fflush(stdout);
//	print_func2();
	unsigned long foo_ret;

	foo_func_t foo2;
	off_t foo2_offset;

	foo_ret = (uint64_t)&printf;
	printf("actual address for printf = %p\n", foo_ret);






	foo2 = (foo_func_t)(offsets.base + offsets.foo2_off);
	printf("foo2 result = %p\n", foo2());


	foo2 = (foo_func_t)(blob + offsets.foo_off);

	foo_ret = foo2();
	printf("address of foo = %p\n", foo_ret);

//	foo2 = (foo_func_t)(blob + offsets.foo2_off);
//	foo_ret = foo2();
//	printf("foo2 was %p\n", foo_ret);


//	foo_func_t foo3 = (foo_func_t)(blob + offsets.foo3_off);
//	foo_ret = foo3();
//	printf("printf is %p\n", foo_ret);

//	foo_func_t foo4 = (foo_func_t)(blob + offsets.foo4_off);
//	foo_ret = foo4();
//	printf("obj3 says printf might be %p\n", foo_ret);


/* ***** */
	void *dl_handle;
	char *lerror;
//	dl_handle = dlopen("/home/sorenson/RH/case_remnants/C_object_testing/test10", RTLD_LAZY);
	dl_handle = dlopen("/home/sorenson/RH/case_remnants/C_object_testing/test10_lib.o", RTLD_LAZY);
	if (dl_handle) {
		char *bytes = dlsym(dl_handle, "__start_test10");
		lerror = dlerror();
		if (error != NULL) {
			printf("dlsym error: %s\n", lerror);
		} else {
			printf("address is %p\n", bytes);

//set_printf_addr(printf_addr);

			print_func_t print_func3 = (print_func_t)(bytes + offsets.print_off);
			print_func3();
			printf("back from the dead\n");
		}
		dlclose(dl_handle);
	} else {
		printf("dlopen error: %s\n", dlerror());
	}





	return EXIT_SUCCESS;
}
