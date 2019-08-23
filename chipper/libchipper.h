/*
	Frank Sorenson <sorenson@redhat.com>
	Red Hat, 2017

	libchipper - a library to implement rotating logs
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
#include <stdbool.h>

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
extern uint64_t SECTION_SIZE(LIBNAME);


#define FORMAT_PRINTF_ATTRIB(format_idx, arg_idx) \
	__attribute__(( format(printf, format_idx, arg_idx) ))

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)

#define DEFAULT_LOG_ROTATE_SIZE (100ULL * MiB)
#define MIN_LOG_ROTATE_SIZE (10ULL * KiB) /* arbitrary, but that's how I roll */
#define DEFAULT_LOG_BASE "/tmp"
#define DEFAULT_LOG_DIR DEFAULT_LOG_BASE "/chipper_tmp_%d"

#define exit_fail(args...) do { \
	printf(args); exit(EXIT_FAILURE); } while (0)

#define error_exit_fail(args...) do { \
	printf("%s:%d - Error %d: %s - ", __FILE__, __LINE__, errno, strerror(errno)); \
	exit_fail(args); \
} while (0)

enum chipper_tstamp_precision {
	chipper_tstamp_none,
	chipper_tstamp_precision_s,
	chipper_tstamp_precision_ms,
	chipper_tstamp_precision_us,
	chipper_tstamp_precision_ns,
	chipper_tstamp_precision_unix,
	chipper_tstamp_precision_unix_ns,
	chipper_tstamp_precision_MAX
};

#define CHIPPER_LOG_OVERWRITE	0x00000001
#define CHIPPER_LOG_APPEND	0x00000002

#define CHIPPER_QUIET		0x00000010

#define CHIPPER_TSTAMP_SHIFT	12
#define CHIPPER_TSTAMP_MASK1	((1 << CHIPPER_TSTAMP_SHIFT) - 1)
#define CHIPPER_TSTAMP_MASK2	((1 << (CHIPPER_TSTAMP_SHIFT + chipper_tstamp_precision_MAX)) - 1)
#define CHIPPER_TSTAMP_MASK3	(CHIPPER_TSTAMP_MASK2 & ~CHIPPER_TSTAMP_MASK1)
#define CHIPPER_TSTAMP_MASK	CHIPPER_TSTAMP_MASK3

#define chipper_tstamp_set_none(flags) do { flags &= ~CHIPPER_TSTAMP_MASK; } while (0)
#define chipper_tstamp_precision_bit(enumval) (1 << (CHIPPER_TSTAMP_SHIFT + enumval))


#define CHIPPER_TSTAMP_S	chipper_tstamp_precision_get_bit(chipper_tstamp_precision_s)
#define CHIPPER_TSTAMP_MS	chipper_tstamp_precision_get_bit(chipper_tstamp_precision_ms)
#define CHIPPER_TSTAMP_US	chipper_tstamp_precision_get_bit(chipper_tstamp_precision_us)
#define CHIPPER_TSTAMP_NS	chipper_tstamp_precision_get_bit(chipper_tstamp_precision_ns)
#define CHIPPER_TSTAMP_UNIX	chipper_tstamp_precision_get_bit(chipper_tstamp_precision_unix)
#define CHIPPER_TSTAMP_UNIX_NS	chipper_tstamp_precision_get_bit(chipper_tstamp_precision_unix_ns)

#define chipper_tstamp_flag_precision(flags) ({ \
	typeof(flags) _flags = flags & CHIPPER_TSTAMP_MASK; \
	_flags ? ((sizeof(flags) * 8) - __builtin_clz(_flags)) - CHIPPER_TSTAMP_SHIFT - 1 : chipper_tstamp_none; \
})

#define chipper_tstamp_precision_set_bit(flags, enumval) do { \
	flags |= chipper_tstamp_precision_bit(enumval); \
} while (0)

#define chipper_set_quiet(flags) do { \
	flags |= CHIPPER_QUIET; \
} while (0)

#define chipper_tstamp_precision_bit_is_set(flags, enumval) \
	((flags & chipper_tstamp_precision_bit(enumval)) == chipper_tstamp_precision_bit(enumval))


/* need to be accessible externally */
//typedef struct chipper *(*new_chipper_func_t)(const char *output_file);

/* accessible through the chipper object */
typedef struct chipper *(*chipper_init_func_t)(const char *output_file);
typedef int (*chipprintf_func_t)(const char *fmt, ...) FORMAT_PRINTF_ATTRIB(1,2);
typedef ssize_t (*chipwrite_func_t)(const void *buf, ssize_t count);
typedef void (*chipper_exit_func_t)(void);

typedef int (*chipper_set_tstamp_onoff_func_t)(int set);
typedef bool (*chipper_set_quiet_onoff_func_t)(bool set);
typedef enum chipper_tstamp_precision (*chipper_set_tstamp_precision_func_t)(enum chipper_tstamp_precision tsp);
typedef ssize_t (*chipper_get_total_bytes_func_t)(void);
typedef ssize_t (*chipper_set_rotate_bytes_func_t)(ssize_t size);

struct chipper {
	uint32_t magic;
	chipprintf_func_t chipprintf;
	chipwrite_func_t chipwrite;

	chipper_set_tstamp_onoff_func_t set_tstamp_onoff;
	chipper_set_quiet_onoff_func_t set_quiet_onoff;
	chipper_set_tstamp_precision_func_t set_tstamp_precision;
	chipper_get_total_bytes_func_t get_total_bytes;
	chipper_set_rotate_bytes_func_t set_rotate_size;

	chipper_exit_func_t exit;
};
typedef struct chipper chipper_t;
extern struct chipper *new_chipper(const char *output_file, uint32_t flags);

extern ssize_t chipper_output_tstamp(int fd, enum chipper_tstamp_precision tsp); /* output timestamp to fd, independent of chipper */

#endif
