#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <time.h>

struct timespec tstamp_to_timespec(const char *tstamp) {
	char *tstamp_nons;
	struct timespec ts;
	struct tm tm;
	char *p;
	int len;

	len = strlen(tstamp);
	tstamp_nons = malloc(len - 10);
	strncpy(tstamp_nons, tstamp, 19);
	strncpy(tstamp_nons + 19, tstamp + 29, len - 29);

	p = strptime(tstamp_nons, "%F %T %Z", &tm);
	if (*p == '\0') {
		ts.tv_sec = mktime(&tm);
		ts.tv_nsec = strtol(tstamp + 20, &p, 10);
	} else {
		printf("doh!.  p=%s\n", p);
	}
	free(tstamp_nons);
	return ts;
}


char *create_tstamp(void) {
	struct timespec ts;
	struct tm tm_info;
	char time_buffer[32];
	char tzbuf[8];
	char *tstamp;

	clock_gettime(CLOCK_REALTIME, &ts);
	localtime_r(&ts.tv_sec, &tm_info);
	strftime(time_buffer, 32, "%F %T", &tm_info);
	strftime(tzbuf, 8, "%Z", &tm_info);
	asprintf(&tstamp, "%s.%09ld %s", time_buffer, ts.tv_nsec, tzbuf);

	return tstamp;
}



int main(int argc, char *argv[]) {
	struct tm tm;
	char buf[255];
	char *p;
	char *tstamp;
	struct timespec ts;

	tstamp = create_tstamp();
	printf("timestamp = %s\n", tstamp);

	ts = tstamp_to_timespec(tstamp);

	printf("%lu.%09lu\n", ts.tv_sec, ts.tv_nsec);

	free(tstamp);
	return EXIT_SUCCESS;
}


