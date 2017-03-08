#include <stdio.h>
#include <sys/time.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/prctl.h>

#define native_cpuid(func,ax,bx,cx,dx)\
        __asm__ __volatile__ ("cpuid":\
        "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

#define cpuid_ebx(__leaf,__bit) \
        ({ \
                uint32_t _eax, _ebx, _ecx, _edx; \
                native_cpuid(__leaf, _eax, _ebx, _ecx, _edx); \
                _ebx & _bit(__bit); \
        })

#define cpuid_ecx(__leaf,__bit) \
        ({ \
                uint32_t _eax, _ebx, _ecx, _edx; \
                native_cpuid(__leaf, _eax, _ebx, _ecx, _edx); \
                _ecx & _bit(__bit); \
        })
#define cpuid_edx(__leaf,__bit) \
        ({ \
                uint32_t _eax, _ebx, _ecx, _edx; \
                native_cpuid(__leaf, _eax, _ebx, _ecx, _edx); \
                _edx & _bit(__bit); \
        })

static bool check_have_get_tsc(void) {
        int ret;
        int arg2;

        if ((ret = prctl(PR_GET_TSC, &arg2)) != 0) {
                if (ret == EINVAL) /* we're probably an earlier kernel that doesn't understand the prctl ... now what? */
                        return false;
                /* ... */
                return false;
        }

        return true;
}

static bool check_get_tsc(void) { /* if check_have_get_tsc returns true, we can check the value here */
        int ret;
        int arg2;

        if ((ret = prctl(PR_GET_TSC, &arg2)) == 0)
                return arg2 != 0 ? true : false;
        return false;
}

void set_get_tsc(int enable) {
        int ret;
        int arg2 = PR_TSC_SIGSEGV;

        if (enable)
                arg2 = PR_TSC_ENABLE;

        if ((ret = prctl(PR_SET_TSC, arg2)) != 0) {
                /* something went wrong setting this */

        }
}

bool check_have_rdtscp(void) {
        uint32_t ret;

        ret = cpuid_edx(0x80000001, 27);
        return (ret != 0);
}

static int check_have_posix_timers(void) {
        // first, sanity check on _POSIX_TIMERS
        if (! do_sysconf(_SC_TIMERS))
                return 0;

        // make sure _POSIX_CLOCK_SELECTION is okay
        return do_sysconf(_SC_CLOCK_SELECTION);
}

#define CPU_ESTIMATE_CLK_ID CLOCK_REALTIME
#define CPU_ESTIMATE_SLEEP_SEC  0
#define CPU_ESTIMATE_SLEEP_NS   (UINT64_C(500) * NS_PER_MS)

uint64_t estimate_cpu_hz(uint32_t cpu_num) {
        struct timespec sleep_ts;
        struct timespec start_ts, end_ts;
        uint64_t start_tsc, end_tsc;
        struct timespec diff_ts;
        uint64_t diff_tsc;
        long double time_diff;
        long double hz;

        sleep_ts.tv_sec = CPU_ESTIMATE_SLEEP_SEC;
        sleep_ts.tv_nsec = CPU_ESTIMATE_SLEEP_NS;

        set_affinity(cpu_num);

        start_tsc = do_rdtsc(cpu_num);
        clock_gettime(CPU_ESTIMATE_CLK_ID, &start_ts);
        do_nanosleep(CPU_ESTIMATE_CLK_ID, sleep_ts, 0);
        end_tsc = do_rdtsc(cpu_num);
        clock_gettime(CPU_ESTIMATE_CLK_ID, &end_ts);

        diff_tsc = end_tsc - start_tsc;
        diff_ts = diff_timespecs(start_ts, end_ts);

        time_diff = diff_ts.tv_sec + (long double)diff_ts.tv_nsec / NS_PER_SEC_FLOAT;

        hz = (long double)diff_tsc / time_diff;
        system_features.cpu_info[cpu_num].cpu_hz = (typeof(system_features.cpu_info[cpu_num].cpu_hz))hz;
        system_features.cpu_info[cpu_num].cpu_mhz = (system_features.cpu_info[cpu_num].cpu_hz / HZ_PER_MHZ);

        system_features.cpu_info[cpu_num].cpu_cycle_time_ps = (NS_PER_SEC_FLOAT * 1000.0L) / hz;

        return system_features.cpu_info[cpu_num].cpu_hz;
}

























#include <iostream>
using namespace std;


#ifdef __i386__
#  define RDTSC_DIRTY "%eax", "%ebx", "%ecx", "%edx"
#elif __x86_64__
#  define RDTSC_DIRTY "%rax", "%rbx", "%rcx", "%rdx"
#else
# error unknown platform
#endif

int selfAdjustmentConst = 0;
long start_counter = 0;


double NANOS_PER_CYCLE;
uint64_t start_time_sec       = 0;
uint64_t start_time_millis    = 0;
uint64_t start_time_micros    = 0;
uint64_t start_time_nanos     = 0;

#define RDTSC_START(cycles)                                \
    do {                                                   \
        register unsigned cyc_high, cyc_low;               \
        asm volatile("CPUID\n\t"                           \
                     "RDTSC\n\t"                           \
                     "mov %%edx, %0\n\t"                   \
                     "mov %%eax, %1\n\t"                   \
                     : "=r" (cyc_high), "=r" (cyc_low)     \
                     :: RDTSC_DIRTY);                      \
        (cycles) = ((uint64_t)cyc_high << 32) | cyc_low;   \
    } while (0)

#define RDTSC_STOP(cycles)                                 \
    do {                                                   \
        register unsigned cyc_high, cyc_low;               \
        asm volatile("RDTSCP\n\t"                          \
                     "mov %%edx, %0\n\t"                   \
                     "mov %%eax, %1\n\t"                   \
                     "CPUID\n\t"                           \
                     : "=r" (cyc_high), "=r" (cyc_low)     \
                     :: RDTSC_DIRTY);                      \
        (cycles) = ((uint64_t)cyc_high << 32) | cyc_low;   \
    } while(0)

#define RDTSC_IMMEDIATE(cycles)                            \
    do {                                                   \
        register unsigned cyc_high, cyc_low;               \
        asm volatile("RDTSC\n\t"                           \
                     "mov %%edx, %0\n\t"                   \
                     "mov %%eax, %1\n\t"                   \
                     : "=r" (cyc_high), "=r" (cyc_low)     \
                     :: RDTSC_DIRTY);                      \
        (cycles) = ((uint64_t)cyc_high << 32) | cyc_low;   \
    } while (0)
long ZSTART() {
        long c;
        RDTSC_START(c);
        return c;
}

long ZSTOP() {
        long c;
        RDTSC_STOP(c);
        return c - selfAdjustmentConst;
}
long ZIMMEDIATE() {
	long c;
	RDTSC_IMMEDIATE(c);
	return c;
}

long ZTIMESEC() {
	long c;
	RDTSC_IMMEDIATE(c);
	return start_time_sec + (c-start_counter)*NANOS_PER_CYCLE/1000000000;
}

long ZTIMEMILLIS() {
	long c;
	RDTSC_IMMEDIATE(c);
	return start_time_millis + (c-start_counter)*NANOS_PER_CYCLE/1000000;
}

uint64_t ZTIMEMICROS() {
	uint64_t c;
	RDTSC_IMMEDIATE(c);
	return start_time_micros + (c-start_counter)*NANOS_PER_CYCLE/1000;
}

uint64_t ZTIMENANOS() {
	uint64_t c;
	RDTSC_IMMEDIATE(c);
	return start_time_nanos + (c-start_counter)*NANOS_PER_CYCLE;
}


void ZLOG(const std::string& id, long value) {
//	zvalues[id].push_back(value);
}





int init_a() {
	int selfAdjustmentConst = 0;
	long start_counter = 0;


	int COUNT = 1000;
	int sum = 0;
	for(int i = 0; i < COUNT; ++ i ) {
		long t1 = ZSTART();
		long t2 = ZSTOP();
		sum += (t2 - t1);
	}
	selfAdjustmentConst = sum/COUNT;

	printf("selfAdjustmentConst = %d\n", selfAdjustmentConst);


	timeval tbegin, tend;
	long begin = ZSTART();
	gettimeofday(&tbegin, NULL);
	sleep(2);
	gettimeofday(&tend, NULL);
	long end = ZSTOP();



	long cycles = end - begin;
	long micros = (tend.tv_sec - tbegin.tv_sec) * 1000 * 1000 +
		tend.tv_usec - tbegin.tv_usec;

	printf("cycles = %ld, micros=%ld\n", cycles, micros);


	NANOS_PER_CYCLE = micros * 1000.0 / cycles;

	printf("nanos/cycle = %lf\n", NANOS_PER_CYCLE);



	timeval t;
	gettimeofday(&t, NULL);
	start_counter = ZIMMEDIATE();
	start_time_sec    = t.tv_sec;
	start_time_millis = t.tv_sec*1000 + t.tv_usec/1000;
	start_time_micros = t.tv_sec*1000000 + t.tv_usec;
	start_time_nanos  = t.tv_sec*1000000000 + t.tv_usec*1000;




}




int main(int argc, char *argv[]) {
	init_a();

}
