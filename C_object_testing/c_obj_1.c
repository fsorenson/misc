#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include "test6.h"

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


#define PROG_SECTION prog

#define FUNC_SECTION functions
#define FUNC_SECTION_ATTRIBS \
	__attribute__((section(__STR(FUNC_SECTION)), used, aligned(8)))

#define VARS_SECTION vars
#define VARS_SECTION_ATTRIBS \
	__attribute__((section(__STR(VARS_SECTION)), used, aligned(8)))

#define SECTION_START(_section)		__PASTE(__start_, _section)
#define SECTION_STOP(_section)		__PASTE(__stop_, _section)
#define SECTION_SIZE(_section)		__PASTE(__size_, _section)




const int *get_var3_addr(void) {
static int var3 = 123;

asm(
	".pushsection vars, \"?\", @progbits" "\n"
	".quad %c0" "\n"
	".popsection" "\n"
	: : "i"(&var3)
       );

	return &var3;
}

int *get_var3_addr_externally(void) {

}

/*
//#define FUNC_SECTION_ATTRIBS \
//	__attribute__(((section("functions"))), used, aligned(8))
*/
//__attribute__((section(__STR(EXT_CMD_ENTRY_SECTION)), used, aligned(8)))

typedef int (*func1_t)(int);

int var2;

int FUNC_SECTION_ATTRIBS func1(int var1) {
	

//	return var1 + var2;
//	printf("address of var2=%p\n", &var2);
	return var1;
}

#define FUNCTION_SECTION_START SECTION_START(FUNC_SECTION)
#define FUNCTION_SECTION_STOP SECTION_STOP(FUNC_SECTION)
#define FUNCTION_SECTION_SIZE SECTION_SIZE(FUNC_SECTION)

//extern char *FUNCTION_SECTION_START;
extern char __start_functions;
//extern char *FUNCTION_SECTION_STOP;
extern char __stop_functions;
unsigned long FUNCTION_SECTION_SIZE;
//extern char *functions__start;
//extern char *functions__stop;
/*
shared_data->protected_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			                MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

        memset(shared_data->protected_page, PROTECTED_PAGE_POISON_CHAR, 4096);
	        mprotect(shared_data->protected_page, 4096, PROT_NONE);

int function
*/

//static int __attribute__((section("test1_data#"), used, aligned(1))) var4 = 99;
static int __attribute__((section(".text#"))) var4 = 99;

//int __attribute__((section("test1"), used, aligned(8))) *func4() {
int  *func4() {
	/*
asm(
".pushsection test1_data, \"awx\", @progbits" "\n"
".quad %c0" "\n"
".popsection" "\n"
: : "i"(&var4)

);
*/

	return &var4;
}
//__attribute__((section(__STR(FUNC_SECTION)), used, aligned(8)))

static const int __attribute__((section("test5_d"))) var5 = 17;
int __attribute__((section("test5_t"))) *func_var5() {

	return &var5;
}
extern char __start_test5_d;
extern char __stop_test5_d;
extern char __start_test5_t;
extern char __stop_test5_t;
/*
extern char __start_test1;
extern char __stop_test1;
*/



int main(int argc, char *argv[]) {
	int i;
	char *blob;
	int ret;
	func1_t fn = NULL;
	func1_t fn_dup = NULL;


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

//	blob = malloc(FUNCTION_SECTION_SIZE);
//char *d=mmap(0,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANON,-1,0);
//    memset (d,0xc3,4096);

	blob = mmap(0, FUNCTION_SECTION_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
	memcpy(blob, &FUNCTION_SECTION_START, FUNCTION_SECTION_SIZE);
//	ret = mprotect(blob, FUNCTION_SECTION_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);
//	if (ret == -1)
//		printf("error with mprotect: %m\n");
//printf("mprotected\n");

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

/*
printf("about to get var3 addr\n");
	int *var_addr = get_var3_addr();
	printf("var3 is %p, and has value %d\n", var_addr, *var_addr);

	printf("size of get_var3_addr function is %lu\n", sizeof(&get_var3_addr));
fflush(stdout);
*/


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






	printf("%p: __start_test6\n", &__start_test6);
	printf("%p:   test6_offsets, offset = %lu\n", &offsets, (void *)&offsets - (void *)&__start_test6);
	printf("%p:   var6, offset = %lu\n", &var6, (void *)&var6 - (void *)&__start_test6);


	printf("%p: test6_data_end, offset %lu\n", &test6_data_end, &test6_data_end - &__start_test6);
	printf("%p: test6_func_start, offset = %lu\n", &test6_func_start, &test6_func_start - &__start_test6);

	printf("%p:   set_var6_func, offset = %lu\n", &set_var6_func, (void *)&set_var6_func - (void *)&__start_test6);
	printf("%p:   get_var6_func, offset = %lu\n", &get_var6_func, (void *)&get_var6_func - (void *)&__start_test6);
	printf("%p:   print_var6_func, offset = %lu\n", &print_var6_func, (void *)&print_var6_func - (void *)&__start_test6);

	printf("%p: __stop_test6, offset=%lu\n", &__stop_test6, &__stop_test6 - &__start_test6);

	printf("test6_size = %lu\n", test6_size);

	printf("the real size = %lu\n", &__stop_test6 - &__start_test6);



	struct test6_data *test_other_struct = init();

	test_other_struct->set_var(99);
printf("here\n");

	test_other_struct->print_var();



/*
	blob = mmap(0, test6_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
	memcpy(blob, &__start_test6, test6_size);
	fn_dup = (func1_t)blob;
*/

printf("allocated some mem\n");










	return EXIT_SUCCESS;
}

