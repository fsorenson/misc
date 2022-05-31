/*

	gcc -Wall wrapfunc.c -o wrapfunc --verbose-asm -Wa,-aghlms=wrapfunc.s -g -Wl,-relax -Wl,-q -fms-extensions

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <string.h>

#define ___STR(x...)    #x
#define __STR(x...)     ___STR(x)
#define __XSTR(s)       __STR(s)

#define ___PASTE(a,b)           a##b
#define ___PASTE3(a,b,c)        a##b##c
#define __PASTE(a,b)            ___PASTE(a,b)
#define __PASTE3(a,b,c)         ___PASTE3(a,b,c)


extern char __start_foo;
extern char __stop_foo;

#define FOO_FUNC_SECTION "foo,\"awx\"#"
#define FOO_VARS_SECTION "foo,\"awx\",@progbits#"

#define FOO_FUNC_ATTRIBS \
	__attribute__((section(FOO_FUNC_SECTION), used, aligned(8), noinline))
#define FOO_VARS_ATTRIBS \
	__attribute__((section(FOO_VARS_SECTION), used, aligned(8), nocommon))

#define COMMON_FUNC_SECTION "foo_common,\"awx\"#"
#define COMMON_VARS_SECTION "foo_common,\"awx\",@progbits#"

#define COMMON_FUNC_ATTRIBS \
	__attribute__((section(COMMON_FUNC_SECTION), used, aligned(8), noinline))
#define COMMON_VARS_ATTRIBS \
	__attribute__((section(COMMON_VARS_SECTION), used, aligned(8), nocommon))


struct foo_struct;
struct foo_struct_private;

typedef ssize_t (*foo_printf_func_t)(const char *fmt,...);
typedef ssize_t (*printfoo_internal_func_t)(const struct foo_struct_private *self, const char *fmt, va_list ap);



struct foo_struct {
	foo_printf_func_t printfoo;
};

struct foo_struct_private {
	union {
		struct foo_struct public_foo;
		struct foo_struct;
	};
	struct foo_struct_private *me;
	uint64_t my_id;
	char *my_name;
	uint64_t offset;

};

static struct foo_struct_private FOO_VARS_ATTRIBS self;

ssize_t COMMON_FUNC_ATTRIBS _printfoo(const struct foo_struct_private *self, const char *fmt, va_list ap) {
	printf("in %s with foo_struct '%s': ", __func__, self->my_name);
	return vprintf(fmt, ap);
}

ssize_t FOO_FUNC_ATTRIBS printfoo(const char *fmt, ...) {
	va_list ap;
	ssize_t len = 0;
	printfoo_internal_func_t pfoo = _printfoo;

	va_start(ap, fmt);
//	len += *(typeof(_printfoo)) (_printfoo)(self.me, fmt, ap);
	len += pfoo(self.me, fmt, ap);
	va_end(ap);
	return len;
}

static void COMMON_FUNC_ATTRIBS __attribute__((constructor)) __foo_init_internal(void) {
	self.printfoo = printfoo;
}

struct foo_struct *new_foo(const char *name) {
	struct foo_struct_private *foo_base = (struct foo_struct_private *)&__start_foo;
	ssize_t foo_size = &__stop_foo - &__start_foo;
	struct foo_struct_private *tmp;

	posix_memalign((void *)&tmp, 4096, foo_size);
	mprotect(tmp, foo_size, PROT_READ|PROT_WRITE|PROT_EXEC);
//	memset(tmp, 0, foo_size);
	memcpy(tmp, &__start_foo, foo_size);
	tmp->me = tmp;
	tmp->my_name = strdup(name);
	tmp->offset = (uint64_t)tmp - (uint64_t)&__start_foo;
	tmp->printfoo += tmp->offset;
	return (struct foo_struct *)tmp;
}

int main(int argc, char *argv[]) {
	struct foo_struct *foo1;
	struct foo_struct *foo2;

	foo1 = new_foo("foo number 1");
	foo2 = new_foo("foo two, yo!");

	foo1->printfoo("testing\n");
	foo2->printfoo("goober\n");
	foo1->printfoo("wassup\n");



}
