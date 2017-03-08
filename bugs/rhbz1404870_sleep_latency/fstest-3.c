#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sched.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>


#define ITER 100
#define SLEEP_USEC 1000

#define NSEC (1000000000UL)
#define USEC (1000000UL)
#define MSEC (1000UL)


#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define mb()    asm volatile("mfence":::"memory")
#define rmb()   asm volatile("lfence":::"memory")
#define wmb()   asm volatile("sfence"::: "memory")
#define mb2()   asm volatile ("" : : : "memory");
#define nop() __asm__ __volatile__ ("nop")

#define __ALWAYS_INLINE	__attribute__((always_inline))

#define USE_GTOD 1
#define USE_TSC 2
#define USE_CLK_GT 4

#define STOPWATCH USE_GTOD

#if STOPWATCH == USE_TSC
#define CLOCK_UNITS uint64_t

inline uint64_t __ALWAYS_INLINE rdtscp_noaux(void) {
        uint32_t eax, edx;

        asm volatile (".byte 0x0f,0x01,0xf9" : "=a" (eax), "=d" (edx) :: "%ecx", "memory");

        return ((uint64_t)edx << 32) | eax;
}
inline uint64_t __ALWAYS_INLINE rdtscp(uint32_t *paux) {
        volatile uint32_t l_aux;
        uint64_t rax, rdx;

//      asm volatile ("rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (l_aux) : : );
        asm volatile (".byte 0x0f,0x01,0xf9" : "=a" (rax), "=d" (rdx), "=c" (l_aux));
        *paux = l_aux;

        return (rdx << 32) + rax;
}
#define RDTSC_BARRIER_PRE()
#define RDTSC_BARRIER_POST()            \
        __asm__ __volatile__(           \
                "xorl %%eax, %%eax;"    \
                "cpuid;" : : : "%rax", "%rbx", "%rcx", "%rdx", "memory" \
        );
inline uint64_t __ALWAYS_INLINE rdtsc(void) {
        uint32_t low, high;

        RDTSC_BARRIER_PRE();
        __asm__ __volatile__(   \
                "rdtsc"         \
                : "=a"(low),    \
                "=d"(high));
        RDTSC_BARRIER_POST();

        return (uint64_t) high << 32 | low;
}

/* need to find cycle time */
static uint64_t elapsed_usec(uint64_t start, uint64_t stop) {
	return stop > start ? stop - start : start - stop;
}
#define GET_TIME(t) do { t = rdtscp_noaux(); } while (0)

#elif STOPWATCH == USE_GTOD
#define CLOCK_UNITS struct timeval

struct timeval elapsed(const struct timeval start, const struct timeval stop) {
        struct timeval ret, a, b;

        if ((start.tv_sec > stop.tv_sec) || 
                        ((start.tv_sec == stop.tv_sec) && (start.tv_usec > stop.tv_usec))) {
                a = stop; b = start;
        } else {
                b = stop; a = start;
        }

        ret.tv_sec = b.tv_sec - a.tv_sec;
        ret.tv_usec = b.tv_usec - a.tv_usec;
        if (ret.tv_usec < 0) {
                ret.tv_usec += USEC;
                ret.tv_sec--;
        }
        return ret;
}
static uint64_t elapsed_usec(const struct timeval start, const struct timeval stop) {
	struct timeval tv = elapsed(start, stop);
	return (tv.tv_sec * USEC) + tv.tv_usec;
}
#define GET_TIME(t) do { gettimeofday(&t, NULL); } while (0)


#elif STOPWATCH == USE_CLK_GT

#define CLOCK_UNITS struct timespec
#define CLOCK_ID CLOCK_REALTIME

struct timespec elapsed(const struct timespec start, const struct timespec stop) {
        struct timespec ret, a, b;

        if ((start.tv_sec > stop.tv_sec) || 
        ((start.tv_sec == stop.tv_sec) && (start.tv_nsec > stop.tv_nsec))) {
                a = stop; b = start;
        } else {
                b = stop; a = start;
        }

        ret.tv_sec = b.tv_sec - a.tv_sec;
        ret.tv_nsec = b.tv_nsec - a.tv_nsec;
        if (ret.tv_nsec < 0) {
                ret.tv_nsec += NSEC;
                ret.tv_sec--;
        }
        return ret;
}

static uint64_t elapsed_usec(const struct timespec start, const struct timespec stop) {
	struct timespec ts = elapsed(start, stop);
	return (tv.tv_sec * NSEC) + tv.tv_nsec;
}

#define GET_TIME(t) do { clock_gettime(CLOCK_ID, &t); } while (0)

#endif





void set_affinity(int cpu) {
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET((size_t)cpu, &mask);

	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
}

struct sample {
	CLOCK_UNITS t;
	uint64_t tsc;
	int64_t diff_usec;
	int64_t overhead_usec;
};

int main(int argc, char *argv[]) {
	int i;
	struct sample samples[ITER + 1];
	int sleep_time = SLEEP_USEC;

	if (argc > 1)
		sleep_time = atoi(argv[1]);
	if (argc == 3) {
		set_affinity(atoi(argv[2]));
	}

	for (i = 0 ; i < ITER ; i ++) {
		GET_TIME(samples[i].t);
		usleep(sleep_time);
	}
	GET_TIME(samples[i].t);

	int64_t total = 0;
	for (i = 0 ; i < ITER - 1 ; i ++) {
		samples[i].diff_usec = elapsed_usec(samples[i].t, samples[i + 1].t);
		samples[i].overhead_usec = samples[i].diff_usec - sleep_time;
		total += samples[i].overhead_usec;
	}
	printf("mean overhead: %" PRId64 "\n", total / ITER);

	return EXIT_SUCCESS;
}
