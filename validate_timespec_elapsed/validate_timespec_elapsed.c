#include <stdio.h>
#include <stdlib.h>

#define NSEC (1000000000UL)
#define USEC (1000000UL)
#define MSEC (1000UL)

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

#define TS_OUTPUT_FORMAT	"{.tv_sec=%ld, .tv_nsec=%ld}"
#define TS_OUTPUT_VARS(v)	v.tv_sec, v.tv_nsec

//#define check_elapsed(a,b,expected) ({ \

#define check_elapsed(a1, a2, b1, b2, e1, e2) ({ \
	struct timespec a = {.tv_sec = a1, .tv_nsec = a2 }; \
	struct timespec b = {.tv_sec = b1, .tv_nsec = b2 }; \
	struct timespec expected = {.tv_sec = e1, .tv_nsec = e2 }; \
	struct timespec ret = elapsed((struct timespec){a1, a2},(struct timespec){b1, b2}); \
	int err = 0; \
\
	if ((ret.tv_sec != expected.tv_sec) || (ret.tv_nsec != expected.tv_nsec)) { \
		printf("FAIL:  elapsed(" TS_OUTPUT_FORMAT ", " TS_OUTPUT_FORMAT ") " \
			"returned " TS_OUTPUT_FORMAT ", but expected " \
			TS_OUTPUT_FORMAT "\n", \
			TS_OUTPUT_VARS(a), TS_OUTPUT_VARS(b), \
			TS_OUTPUT_VARS(ret), TS_OUTPUT_VARS(expected)); \
			err = 1; \
	} else \
	printf("SUCCESS: elapsed(" TS_OUTPUT_FORMAT ", " TS_OUTPUT_FORMAT ") " \
		" = " TS_OUTPUT_FORMAT "\n", \
		TS_OUTPUT_VARS(a), TS_OUTPUT_VARS(b), TS_OUTPUT_VARS(expected)); \
	err; \
})



int main(int argc, char *argv[]) {
	int err = 0;
	

//	err += check_elapsed({0,0}, {1,1}, {1,1});
	err += check_elapsed(0,0, 1,1, 1,1);
	err += check_elapsed(1,1, 1,1, 0,0);
	err += check_elapsed(1,1, 0,0, 1,1);
	err += check_elapsed(2,999999999, 3,1, 0,2);
	err += check_elapsed(3, 1, 2,999999999, 0,2);
	err += check_elapsed(3, 1, 3,999999999, 0,999999998);

	err += check_elapsed(4, 500000000, 3,100000000, 1,400000000);
	err += check_elapsed(3, 100000000, 4,500000000, 1,400000000);


	return EXIT_SUCCESS;
}

