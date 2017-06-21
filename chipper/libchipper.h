/*
	Frank Sorenson <sorenson@redhat.com>
	Red Hat, 2017

	libchipper - a library to implement rotating logs

	usage:

*/
#ifndef __LIBCHIPPER_H__
#define __LIBCHIPPER_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <stdarg.h>
#include <dlfcn.h>

#define LIBNAME libchipper
#define LIBVERSION "0.1.0"


#define ___PASTE(a,b)		a##b
#define ___PASTE3(a,b,c)	a##b##c
#define __PASTE(a,b)		___PASTE(a,b)
#define __PASTE3(a,b,c)		___PASTE3(a,b,c)


#define SECTION_START(_section)	__PASTE(__start_, _section)
#define SECTION_STOP(_section)	__PASTE(__stop_, _section)
#define SECTION_SIZE(_section)	__PASTE(__size_, _section)

extern char SECTION_START(LIBNAME);
extern char SECTION_STOP(LIBNAME);
//extern void *SECTION_SIZE(LIBNAME);
extern ssize_t SECTION_SIZE(LIBNAME);


extern uint64_t THE_START_SPOT;
extern uint64_t THE_END_SPOT;

#define FORMAT_PRINTF_ATTRIB(format_idx, arg_idx) \
	__attribute__(( format(printf, format_idx, arg_idx) ))

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)

#define DEFAULT_LOG_ROTATE_SIZE (100ULL * MiB)
#define MIN_LOG_ROTATE_SIZE (10ULL * KiB) /* arbitrary, but that's how I roll */
#define DEFAULT_LOG_BASE "/tmp"
#define DEFAULT_LOG_DIR DEFAULT_LOG_BASE "/chipper_tmp_%d"


enum tstamp_precision {
	tstamp_none,
	tstamp_precision_s,
	tstamp_precision_ms,
	tstamp_precision_us,
	tstamp_precision_ns
};


/* need to be accessible externally */
//typedef struct chipper *(*new_chipper_func_t)(const char *output_file);

/* accessible through the chipper object */
typedef struct chipper *(*chipper_init_func_t)(const char *output_file);
typedef int (*chipprintf_func_t)(const char *fmt, ...) FORMAT_PRINTF_ATTRIB(1,2);
typedef ssize_t (*chipwrite_func_t)(const void *buf, ssize_t count);
typedef void (*chipper_exit_func_t)(void);

typedef int (*chipper_set_tstamp_onoff_func_t)(int set);
typedef enum tstamp_precision (*chipper_set_tstamp_precision_func_t)(enum tstamp_precision tsp);
typedef int (*chipper_set_tstamp_fmt_func_t)(const char *fmt);
typedef ssize_t (*chipper_get_total_bytes_func_t)(void);
typedef ssize_t (*chipper_set_rotate_bytes_func_t)(ssize_t size);

struct chipper {
	uint32_t magic;
	chipprintf_func_t chipprintf;
	chipwrite_func_t chipwrite;

	chipper_set_tstamp_onoff_func_t set_tstamp_onoff;
	chipper_set_tstamp_precision_func_t set_tstamp_precision;
	chipper_set_tstamp_fmt_func_t set_tstamp_format;
	chipper_get_total_bytes_func_t get_total_bytes;
	chipper_set_rotate_bytes_func_t set_rotate_size;

	chipper_exit_func_t exit;
};
typedef struct chipper chipper_t;
extern struct chipper *new_chipper(const char *output_file);

#endif
