/*

	Frank Sorenson <sorenson@redhat.com>, 2020

	gcc /tmp/preload_mount.c -o /tmp/preload_mount.so -Wall -shared -fPIC -rdynamic -lunwind

	LD_PRELOAD=/tmp/preload_mount.so /bin/ls

	memory trace will output to stderr by default.  Target can be changed
	at runtime by setting MEM_HOOK_OUTPUT:
		MEM_HOOK_OUTPUT=/tmp/trace LD_PRELOAD=/tmp/preload_mount.so mount [options]
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <regex.h>
#include <string.h>
#include <limits.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#define DEFAULT_OUTPUT_FD 2
#define DEFAULT_OUTPUT_FILE stderr

#define FRAMES 32

#define REPLACE_CALLOC 1
#define REPLACE_MALLOC 1
#define REPLACE_REALLOC 1
#define REPLACE_FREE 1
#define REPLACE_MEMALIGN 1

#define REPLACE_MOUNT 1

#define REGEX_MATCH_ELEMENTS 10
#define MAX_ERROR_MSG 0x1000

#define FUNCNAME_MAX 256  /* arbitrary, but it's how I roll */

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

typedef void *(*calloc_t)(size_t nmemb, size_t size);
typedef void *(*malloc_t)(size_t size);
typedef void *(*realloc_t)(void *ptr, size_t size);
typedef void (*free_t)(void *ptr);
typedef void *(*memalign_t)(size_t alignment, size_t size);

typedef int (*mount_t)(const char *source, const char *target,
	const char *filesystemtype, unsigned long mountflags,
	const void *data);


struct funcs {
	malloc_t malloc;
	calloc_t calloc;
	realloc_t realloc;
	free_t free;
	memalign_t memalign;
	mount_t mount;
};

struct funcs real_funcs;

struct config {
	int output_fd;
	FILE *output_file;
	regex_t match_reg;
	bool initializing;
	bool initialized;
	bool trace_enabled;
};

static struct config config = {
	.output_fd = DEFAULT_OUTPUT_FD,
	.initializing = false,
	.initialized = false,
	.trace_enabled = false
};

#define output(args...) do { \
	fprintf(config.output_file, args); \
} while (0)

#define get_func(_handle, _func) ({ \
	char *error; \
	void *_ret = dlsym(_handle, #_func); \
	if ((error = dlerror()) != NULL) { \
		output("%s getting %s\n", error, #_func); \
		exit(EXIT_FAILURE); \
	} \
	_ret; })

static void init(void) {
	void *handle;
	char *mem_hook_output;
	int ret;

	config.initializing = true;
	handle = RTLD_NEXT;

	mem_hook_output = getenv("MEM_HOOK_OUTPUT");
	if (mem_hook_output) {
		if ((config.output_fd = open(mem_hook_output,
				O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IROTH)) > 0) {
			if (! (config.output_file = fdopen(config.output_fd, "a+"))) {
				close(config.output_fd);
				config.output_fd = DEFAULT_OUTPUT_FD;
			}
		} else {
			config.output_fd = DEFAULT_OUTPUT_FD;
		}
	} else {
		config.output_fd = DEFAULT_OUTPUT_FD;
		config.output_file = DEFAULT_OUTPUT_FILE;
	}

	dlerror(); /* clear out any existing errors */

#if REPLACE_CALLOC
	real_funcs.calloc = get_func(handle, calloc);
#endif

#if REPLACE_MALLOC
	real_funcs.malloc = get_func(handle, malloc);
#endif

#if REPLACE_REALLOC
	real_funcs.realloc = get_func(handle, realloc);
#endif

#if REPLACE_FREE
	real_funcs.free = get_func(handle, free);
#endif

#if REPLACE_MEMALIGN
	real_funcs.memalign = get_func(handle, memalign);
#endif

	char *regex_string = "^([-/a-zA-Z0-9_.]+)\\(([a-zA-Z0-9_]+|)(\\+|)(0x[0-9a-fA-F]+|)\\) \\[(0x[0-9a-fA-F]+)\\]";
	if ((ret = regcomp(&config.match_reg, regex_string, REG_EXTENDED)) != 0) {
		output("regcomp returned %d\n", ret);
	}

	config.initialized = true;
	config.initializing = false;
	config.trace_enabled = true;
}

int print_backtrace() {
	regmatch_t regex_matches[REGEX_MATCH_ELEMENTS];

	char filename[PATH_MAX];
	char funcname[FUNCNAME_MAX];
	unsigned long offset;

	char unwind_funcname[FUNCNAME_MAX];
	unw_word_t unwind_offset;

	void *array[FRAMES];	/* store backtrace pointers */
	int size;		/* store the number of values */
	char **bt_strings;		/* store functions from backtrace list */
	int i;
	int bt_ret;

	unw_cursor_t cursor; unw_context_t uc;
	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);

	size = backtrace(array, FRAMES);
	bt_strings = backtrace_symbols(array, size);

	/* skip first frame */
	unw_step(&cursor);

	/* print the function name strings */
	/* but skip the first two, which we're */
	/* using for the backtrace itself */
	i = 2;
	while ((i < size) && (unw_step(&cursor) > 0)) {

		unw_get_proc_name(&cursor, unwind_funcname, FUNCNAME_MAX, &unwind_offset);

		if ((bt_ret = regexec(&config.match_reg, bt_strings[i], REGEX_MATCH_ELEMENTS, regex_matches, 0)) != 0) {
			char error_message[MAX_ERROR_MSG];
			regerror(bt_ret, &config.match_reg, error_message, MAX_ERROR_MSG);

			output("failed to match '%s'...  error was %s\n",
				bt_strings[i], error_message);
			continue;
		}

		// going to assume array[i] == unwind_ip == the dl IP
		memset(filename, 0, PATH_MAX);
		if (regex_matches[1].rm_so >= 0)
			strncpy(filename, bt_strings[i] + regex_matches[1].rm_so,
				regex_matches[1].rm_eo - regex_matches[1].rm_so);

		memset(funcname, 0, FUNCNAME_MAX);
		if (regex_matches[2].rm_so >= 0)
			strncpy(funcname, bt_strings[i] + regex_matches[2].rm_so, regex_matches[2].rm_eo - regex_matches[2].rm_so);

		// if bt didn't have funcname, check unwind
		if (funcname[0] == '\0')
			strncpy(funcname, unwind_funcname, FUNCNAME_MAX);

		// try just using the unwind offset, otherwise we could probably get the offset
		//   from 'bt_strings[i] + regex_matches[4].rm_so'
		offset = unwind_offset;

		output("\t0x%lx: %s %s()+0x%lx\n", (unsigned long)array[i], filename, funcname, offset);

		i++;
	}
	output("\n");

	return 0;
}

#if REPLACE_CALLOC
void *calloc(size_t nmemb, size_t size) {
	if (config.initializing) {
		extern void *__libc_calloc(size_t, size_t);
		return __libc_calloc(nmemb, size);
	}

	if (!config.initialized)
		init();

	void *ret = real_funcs.calloc(nmemb, size);

	if (config.trace_enabled) {
		config.trace_enabled = false;
		output("calloc(%lu, %lu) = %lu bytes = %p\n", nmemb, size, nmemb * size, ret);
		print_backtrace();
		config.trace_enabled = true;
	}
	return ret;
}
#endif

#if REPLACE_MALLOC
void *malloc(size_t size) {
	if (config.initializing) {
		extern void *__libc_malloc(size_t);
		return __libc_malloc(size);
	}

	if (!config.initialized)
		init();

	void *ret = real_funcs.malloc(size);

	if (config.trace_enabled) {
		config.trace_enabled = false;
		output("malloc(%lu total bytes) = %p\n", size, ret);
		print_backtrace();
		config.trace_enabled = true;
	}
	return ret;
}
#endif

#if REPLACE_REALLOC
void *realloc(void *ptr, size_t size) {
	if (config.initializing) {
		extern void *__libc_realloc(void *, size_t);
		return __libc_realloc(ptr, size);
	}

	if (!config.initialized)
		init();

	void *ret = real_funcs.realloc(ptr, size);

	if (config.trace_enabled) {
		config.trace_enabled = false;
		output("realloc(%p, %lu) =  %p\n", ptr, size, ret);
		print_backtrace();
		config.trace_enabled = true;
	}
	return ret;
}
#endif

#if REPLACE_FREE
void free(void *ptr) {
	if (unlikely(config.initializing)) {
		extern void __libc_free(void *);
		__libc_free(ptr);
		return;
	}
	if (unlikely(ptr == NULL))
		return;

	if (unlikely(!config.initialized))
		init();

	if (config.trace_enabled) {
		config.trace_enabled = false;
		output("free(%p allocation)\n", ptr);
		print_backtrace();
		config.trace_enabled = true;
	}

	real_funcs.free(ptr);
}
#endif

#if REPLACE_MEMALIGN
void *memalign(size_t alignment, size_t size) {
	if (config.initializing) {
		extern void __libc_memalign(size_t, size_t);
		__libc_memalign(alignment, size);
	}

	if (!config.initialized)
		init();

	void *ret = real_funcs.memalign(alignment, size);

	if (config.trace_enabled) {
		config.trace_enabled = false;
		output("memalign(%lu, %lu) = %p\n", alignment, size, ret);
		config.trace_enabled = true;
	}
	return ret;
}
#endif

#if REPLACE_MOUNT
int mount(const char *source, const char *target,
	const char *filesystemtype, unsigned long mountflags,
	const void *data) {

	if (config.initializing) {
		extern int __libc_mount(size_t, size_t);
		__libc_memalign(alignment, size);
	}
		extern void *__libc_realloc(void *, size_t);
		return __libc_realloc(ptr, size);

	if (!config.initialized)
		init();

	void *ret = real_funcs.memalign(alignment, size);

	if (config.trace_enabled) {
		config.trace_enabled = false;
		output("memalign(%lu, %lu) = %p\n", alignment, size, ret);
		config.trace_enabled = true;
	}
	return ret;
}
#endif
