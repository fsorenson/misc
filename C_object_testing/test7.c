#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
//#include "test7.h"

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


#define MAIN_SECTION test7

#define FUNC_SUBSECTION funcs
#define VARS_SUBSECTION vars



#define FUNC_SECTION_ATTRIBS \
	__attribute__((section(__STR(MAIN_SECTION)  "."  __STR(FUNC_SUBSECTION)), used, aligned(8), noinline))
//	__attribute__((section(__PASTE3(__STR(MAIN_SECTION), ".", __STR(FUNC_SUBSECTION))), used, aligned(8)))
#define VARS_SECTION_ATTRIBS \
	__attribute__((section(__STR(MAIN_SECTION) "." __STR(VARS_SUBSECTION)), used, aligned(8)))
//	__attribute__((section(__STR(VARS_SECTION)), used, aligned(8)))

#define SECTION_START(_section)		__PASTE(__start_, _section)
#define SECTION_STOP(_section)		__PASTE(__stop_, _section)
#define SECTION_SIZE(_section)		__PASTE(__size_, _section)

#define FUNCTION_SECTION_START SECTION_START(FUNC_SECTION)
#define FUNCTION_SECTION_STOP SECTION_STOP(FUNC_SECTION)
#define FUNCTION_SECTION_SIZE SECTION_SIZE(FUNC_SECTION)



extern char __start_test7;
extern char __stop_test7;
extern unsigned long __size_test7;
extern unsigned long __var7_section_offset;
extern unsigned long __print_var7_func_offset;
extern unsigned long __print_var7_func_offset2;
typedef int (*set_func_t)(int);
typedef int (*get_func_t)(void);
typedef void (*print_func_t)(void);

extern char __set_var7_func_section_offset;
extern unsigned long __get_var7_func_section_offset;
extern unsigned long __print_var7_func_section_offset;
extern char __start_test7_funcs;



//struct test6_offsets __attribute__((aligned(sizeof(struct test6_offsets)), used, section("test6.vars"))) offsets;
int VARS_SECTION_ATTRIBS var7;

int FUNC_SECTION_ATTRIBS set_var7_func(int val) {
	printf("in %s, func_addr = %p, var7 addr = %p, var7 = %d\n",
		__func__, &set_var7_func, &var7, var7);
	var7 = val;
	return var7;
}
int FUNC_SECTION_ATTRIBS get_var7_func(void) {
	printf("in %s, func_addr = %p, var7 addr = %p, var7 = %d\n",
		__func__, &get_var7_func, &var7, var7);
	return var7;
}
void FUNC_SECTION_ATTRIBS print_var7_func(void) {
//	unsigned long my_offset = (unsigned long)&print_var7_func - __start_test7;
	unsigned long my_offset = &__print_var7_func_offset;

	printf("in %s, func_addr = %p, var7 addr = %p, var7 = %d\n",
		__func__, &print_var7_func, &var7, var7);
	printf("**** offset to this function: %lx\n", my_offset);

//	struct test6_data *base = (void *)(&print_var6_func - offsets.print_var_func);


	printf("var7 = %d\n", var7);
}
//struct test6_data *__attribute((aligned(8), used, section("test6.funcs"))) init() {
void *FUNC_SECTION_ATTRIBS init(void) {
	char *blob;
	void *this_obj = NULL;

/*
	char *blob;
	unsigned long real_size = &__stop_test6 - &__start_test6;
//	struct test6_offsets *tmp_offsets;
	struct test6_data *this_obj;
*/

	/* calculate some offsets */
/*
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
*/
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




int main(int argc, char *argv[]) {
	int i;
	int ret;
//	func1_t fn = NULL;
//	func1_t fn_dup = NULL;

/*
 *
	printf("addrs:  '%s': %p and '%s': %p\n",
		__STR(FUNCTION_SECTION_START), &FUNCTION_SECTION_START,
		__STR(FUNCTION_SECTION_STOP), &FUNCTION_SECTION_STOP);
	printf("size: %lu\n", FUNCTION_SECTION_SIZE);
	FUNCTION_SECTION_SIZE = &FUNCTION_SECTION_STOP - &FUNCTION_SECTION_START;
	printf("size: %lu\n", FUNCTION_SECTION_SIZE);

	for (i = 0 ; i < FUNCTION_SECTION_SIZE ; i++) {
		printf("%02x ", *(char *)(&FUNCTION_SECTION_START + i) & 0xff);
	}
	printf("\n");
*/


//	blob = malloc(FUNCTION_SECTION_SIZE);
//char *d=mmap(0,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANON,-1,0);
//    memset (d,0xc3,4096);

//	blob = mmap(0, FUNCTION_SECTION_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
//	memcpy(blob, &FUNCTION_SECTION_START, FUNCTION_SECTION_SIZE);
//	ret = mprotect(blob, FUNCTION_SECTION_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);
//	if (ret == -1)
//		printf("error with mprotect: %m\n");
//printf("mprotected\n");

/*
	for (i = 0 ; i < FUNCTION_SECTION_SIZE ; i++) {
		printf("%02x ", blob[i] & 0xff);
	}
	printf("\n");
	fn = (func1_t)blob;

	blob = mmap(0, FUNCTION_SECTION_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
	memcpy(blob, &FUNCTION_SECTION_START, FUNCTION_SECTION_SIZE);
	fn_dup = (func1_t)blob;

	printf("fn=%p\n", fn);
	char *p = (char *)fn;
	for (i = 0 ; i < FUNCTION_SECTION_SIZE ; i++) {
		printf("%02x ", *(p + i) & 0xff);
	}
	printf("\n");

*/
/*
printf("about to get var3 addr\n");
	int *var_addr = get_var3_addr();
	printf("var3 is %p, and has value %d\n", var_addr, *var_addr);

	printf("size of get_var3_addr function is %lu\n", sizeof(&get_var3_addr));
fflush(stdout);
*/

/*
	ret = fn(1);
	printf("ret = %d\n", ret);
	printf("result 1: %d\n", fn(1));


	printf("fn_dup = %p\n", fn_dup);
	printf("fn_dup val = %d\n", fn_dup(1));

fflush(stdout);

//	printf("test1 section: %p - %p\n", &__start_test1, &__stop_test1);
	int *var4_addr = func4();
	printf("var4_addr = %p\n", var4_addr);

	printf("func4:\n\taddr: %p\n\tret:  %p\n\tval:  %d\n", func4, func4(), *func4());

	printf("var5 = %p\n", &var5);
	printf("func_var5 = %p\n", func_var5);
	printf("test5_d = %p - %p\n", &__start_test5_d, &__stop_test5_d);
	printf("test5_t = %p - %p\n", &__start_test5_t, &__stop_test5_t);


	printf("setting var6 to 400\n");
	set_var6_func(400);
	printf("var6 = %d\n", get_var6_func());
//	struct test6 t6;
//	printf("p_t6 = %p\n", &t6);

	printf("setting var6 to 18\n");
	set_var6_func(18);
	printf("var6 = %d\n", get_var6_func());


	printf("Calling print_var6_func()\n");
	print_var6_func();

	printf("setting var6 to 356\n");
	set_var6_func(356);
	printf("var6 = %d\n", get_var6_func());

	printf("offsets starts at %p\n", &offsets);

*/

	printf("running the program\n");
	set_var7_func(700);
	print_var7_func();
	set_var7_func(14);
	print_var7_func();
	set_var7_func(8);
	print_var7_func();





	unsigned long base_addr = (unsigned long)&__start_test7;
	printf("base addr = %p\n", base_addr);

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




/*
	printf("%p: __start_test7\n", &__start_test7);
	printf("%p:  var7\n", (unsigned long)&var7 - base_addr);
//	printf("%p: __var7_section_offset, %d?\n", __var7_section_offset, *(unsigned long *)__var7_section_offset);
	printf("%p: __var7_section_offset, %p?\n", __var7_section_offset, &__var7_section_offset);

	printf("*** %d ***\n", *(unsigned long *)0x600000);
	printf("%p: __set_var7_func_section_offset, %p\n", __set_var7_func_section_offset, &__set_var7_func_section_offset);


	printf("%p:  set_var7_func\n", &set_var7_func);
	printf("%p:  get_var7_func\n", &get_var7_func);
	printf("%p:  print_var7_func\n", &print_var7_func);
	printf("%p: __stop_test7\n", &__stop_test7);

	printf("__size_test7 = %lu\n", __size_test7);
	printf("__size_test7 = %lu\n", &__stop_test7 - &__start_test7);
*/


	unsigned long test7_size = &__stop_test7 - &__start_test7;
	printf("allocating %d bytes\n", test7_size);
	char *blob = mmap(0, &__stop_test7 - &__start_test7, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
	memcpy(blob, &__start_test7, test7_size);


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





//	printf("%p: __start_test7\n", &__start_test7);
//	printf("%p: __start_test7_funcs\n", &__start_test7_funcs);
/*
//	printf("%p:   test7, offset = %lu\n", &offsets, (void *)&offsets - (void *)&__start_test7);
	printf("%p:   var7, offset = %lu\n", &var7, (void *)&var7 - (void *)&__start_test7);
*/

//	printf("%p: test7_data_end, offset %lu\n", &test7_data_end, &test7_data_end - &__start_test7);
//	printf("%p: test7_func_start, offset = %lu\n", &test7_func_start, &test7_func_start - &__start_test7);

/*
	printf("%p:   set_var7_func, offset = %lu\n", &set_var7_func, (void *)&set_var7_func - (void *)&__start_test7);
	printf("%p:   get_var7_func, offset = %lu\n", &get_var7_func, (void *)&get_var7_func - (void *)&__start_test7);
	printf("%p:   print_var7_func, offset = %lu\n", &print_var7_func, (void *)&print_var7_func - (void *)&__start_test7);

	printf("%p: __stop_test7, offset=%lu\n", &__stop_test7, &__stop_test7 - &__start_test7);

	printf("test7_size = %lu\n", test7_size);

	printf("the real size = %lu\n", &__stop_test7 - &__start_test7);
*/

/*
	struct test7_data *test_other_struct = init();

	test_other_struct->set_var(99);
printf("here\n");

	test_other_struct->print_var();
*/


/*
	blob = mmap(0, test7_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
	memcpy(blob, &__start_test7, test7_size);
	fn_dup = (func1_t)blob;
*/











	return EXIT_SUCCESS;
}

