#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>


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


void *libc_handle;
#define typedefof(func) __PASTE(func,_func_t)
//#define typedef_func_sym(func) typedef typeof(func) #func#func_t;
#define typedef_func_sym(func) typedef typeof(func) typedefof(func)

#define tramp_func_sym(func) typedefof(func) *func

//typedef typeof(asprintf) typedefof(asprintf);

#define load_sym(sym) do { \
	char *error = NULL; \
	dlerror(); \
	trampolines.sym = (__PASTE(sym,_func_t) *)dlsym(libc_handle, __STR(sym)); \
	if ((error = dlerror()) != NULL) { \
		/* uh oh...  what now? */ \
	} \
} while (0)

int asprintf(char **strp, const char *fmt, ...);

typedef  int(asprintf_func_t)(char **strp, const char*fmt, ...);
//typedef typeof(asprintf) asprintf_type_t;




typedef_func_sym(open);
typedef_func_sym(close);

struct trampoline_struct {
	tramp_func_sym(open);
	tramp_func_sym(close);
};

int main(int argc, char *argv[]) {
	int v = 88;
	struct trampoline_struct trampolines;

	load_sym(open);
	load_sym(close);


	printf("v=%d\n", v);

	return EXIT_SUCCESS;
}

