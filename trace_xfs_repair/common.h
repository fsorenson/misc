#ifndef __COMMON_H__
#define __COMMON_H__

#define _GNU_SOURCE
#include <stdio.h>


#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
//#define nop()   __asm__ __volatile__ ("nop")
#define PASTE(a, b) a##b
#define XSTR(a) #a

#define KiB (1024ULL)
#define MiB (KiB * KiB)
#define GiB (KiB * KiB * KiB)
#define TiB (KiB * KiB * KiB * KiB)

#define STACK_SIZE (64 * KiB)


#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)


//#if DEBUG
#if 1
#define debug_output(args...) do { \
        output(args); \
} while (0)
#else
#define debug_output(args...) do { \
} while (0)
#endif

#define min(a,b) ({ \
        typeof(a) _a = (a); \
        typeof(b) _b = (b); \
        _a < _b ? _a : _b; \
})
#define max(a,b) ({ \
        typeof(a) _a = (a); \
        typeof(b) _b = (b); \
        _a > _b ? _a : _b; \
})

#define free_mem(ptr) do { \
	if (ptr) \
		free(ptr); \
	ptr = NULL; \
} while (0)


#endif
