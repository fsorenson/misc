#include <stdio.h>
#include <sys/time.h>
#include <stdint.h>
#include <unistd.h>


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
