#include <stdio.h>



typedef int (*set_var_func_t)(int);
typedef int (*get_var_func_t)(void);
typedef void (*print_var_func_t)(void);


struct test6_offsets {
	unsigned long offsets;
	unsigned long var;
	unsigned long data_end;

	unsigned long func_start;
	unsigned long set_var_func;
	unsigned long get_var_func;
	unsigned long print_var_func;
	unsigned long func_end;
} offsets;

struct test6_data {
	unsigned long var;

	set_var_func_t set_var;
	get_var_func_t get_var;
	print_var_func_t print_var;
};



struct test6_offsets offsets;
int var6;


int set_var6_func(int val);
int get_var6_func();
void print_var6_func();

struct test6_data *init();

extern char __start_test6;
extern char test6_data_end;
extern char test6_func_start;
extern char __stop_test6;
extern unsigned long test6_size;


