#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <dirent.h>
#include <signal.h>


#define KiB (1024ULL)
#define MiB (KiB * KiB)

#define MSEC (1000ULL)
#define USEC (1000000ULL)
#define NSEC (1000000000ULL)


#define STR(s) #s
#define XSTR(s) STR(s)
#define PASTE(a, b) a##b

#define PASTE_INDIR(a, b) PASTE(a, b)
#define INDIR(a) a

#define GETDENTS_BUFSIZE	(64ULL * KiB)

#define STAT_USE_STATX 1
#if STAT_USE_STATX
	#define STAT_SYSCALL_NAME statx

	#define STAT_SYSCALL(_dfd, _name, _buf) statx(_dfd, _name, AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT, STATX_BASIC_STATS, (struct statx *)_buf)
//	statx(dfd, de->d_name, AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT, STATX_BASIC_STATS, (struct statx *)&statbuf);

#else
	#define STAT_SYSCALL_NAME fstatat
	#define STAT_SYSCALL(_dfd, _name, _buf) fstatat(_dfd, _name, (struct stat *)_buf, AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT)
//	fstatat(dfd, de->d_name, (struct stat *)&statbuf, AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT);
#endif
const char *stat_syscall_name = XSTR(STAT_SYSCALL_NAME);

static bool interrupted = false;
struct stats_struct {
	struct timespec getdents_elapsed;
	struct timespec getdents_max;

	struct timespec PASTE_INDIR(STAT_SYSCALL_NAME,_elapsed);
	struct timespec PASTE_INDIR(STAT_SYSCALL_NAME, _max);

	struct timespec openat_elapsed;
	struct timespec openat_max;

	struct timespec close_elapsed;
	struct timespec close_max;

	uint64_t getdents_call_count;
	uint64_t dirent_count;
	uint64_t PASTE_INDIR(STAT_SYSCALL_NAME, _call_count);
	uint64_t openat_call_count;
	uint64_t close_call_count;
};
struct stats_struct overall_stats = { 0 };

struct linux_dirent64 {
	ino64_t         d_ino;
	off64_t         d_off;
	unsigned short  d_reclen;
	unsigned char   d_type;
	char            d_name[];
};

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define exit_fail(args...) do { \
	output("Error %d: %s - ", errno, strerror(errno)); \
	output(args); \
	exit(EXIT_FAILURE); \
} while (0)


struct stopwatch {
	struct timespec start;
	struct timespec stop;
	struct timespec elapsed;
};
#define DEFINE_STOPWATCH(_str) struct stopwatch PASTE(stopwatch_, _str) = { 0 };
#define STOPWATCH_START(_str) do { \
	clock_gettime(CLOCK_REALTIME, &PASTE(stopwatch_, _str).start); \
} while (0)
#define STOPWATCH_STOP(_str) do { \
	clock_gettime(CLOCK_REALTIME, &PASTE(stopwatch_, _str).stop); \
	PASTE(stopwatch_, _str).elapsed = ts_elapsed(PASTE(stopwatch_, _str).start, PASTE(stopwatch_, _str).stop); \
} while (0)
#define STOPWATCH_READ_ELAPSED(_str) (PASTE(stopwatch_, _str).elapsed)
#define STOPWATCH_READ_START(_str) (PASTE(stopwatch_, _str).start)
#define STOPWATCH_READ_STOP(_str) (PASTE(stopwatch_, _str).stop)

#define incr_overall_stats(_type) do { \
	if (ts_gt(subdir_stats.PASTE(_type, _max), overall_stats.PASTE(_type, _max))) \
		overall_stats.PASTE(_type, _max) = subdir_stats.PASTE(_type, _max); \
	overall_stats.PASTE(_type, _elapsed) = add_ts(overall_stats.PASTE(_type, _elapsed), subdir_stats.PASTE(_type, _elapsed)); \
	overall_stats.PASTE(_type, _call_count) += subdir_stats.PASTE(_type, _call_count); \
	if (!strcmp(STR(_type), "getdents")) \
		overall_stats.dirent_count += subdir_stats.dirent_count; \
} while (0)

#define incr_subdir_stats(_type) do { \
	if (ts_gt(STOPWATCH_READ_ELAPSED(_type), subdir_stats.PASTE(_type, _max))) \
		subdir_stats.PASTE(_type, _max) = STOPWATCH_READ_ELAPSED(_type); \
	subdir_stats.PASTE(_type, _elapsed) = add_ts(subdir_stats.PASTE(_type, _elapsed), STOPWATCH_READ_ELAPSED(_type)); \
	subdir_stats.PASTE(_type, _call_count) ++; \
} while (0)


// overall_stats is program global
// subdir_stats is function-local
#define __output_getdents_summary_stat(_summary_type) do { \
	struct timespec mean_time; \
\
	mean_time = mean_ts(PASTE(_summary_type,_stats).getdents_elapsed, PASTE(_summary_type, _stats).getdents_call_count); \
	output("    getdents - calls: %lu, elapsed: %lu.%09lu, mean: %lu.%09lu, max: %lu.%09lu, dirent count: %lu\n", \
		PASTE(_summary_type, _stats).getdents_call_count, \
		PASTE(_summary_type, _stats).getdents_elapsed.tv_sec, PASTE(_summary_type, _stats).getdents_elapsed.tv_nsec, \
		mean_time.tv_sec, mean_time.tv_nsec, \
		PASTE(_summary_type, _stats).getdents_max.tv_sec, PASTE(_summary_type, _stats).getdents_max.tv_nsec, \
		PASTE(_summary_type, _stats).dirent_count); \
} while (0)

#define __output_one_summary_stat(_summary_type, _stat_type) do { \
	struct timespec mean_time; \
\
	mean_time = mean_ts(PASTE(_summary_type, _stats).PASTE(_stat_type, _elapsed), PASTE(_summary_type, _stats).PASTE(_stat_type, _call_count)); \
	output("    %s - calls: %lu, elapsed: %lu.%09lu, mean: %lu.%09lu, max: %lu.%09lu\n", \
		STR(_stat_type), PASTE(_summary_type, _stats).PASTE(_stat_type, _call_count), \
		PASTE(_summary_type, _stats).PASTE(_stat_type, _elapsed).tv_sec, PASTE(_summary_type, _stats).PASTE(_stat_type, _elapsed).tv_nsec, \
		mean_time.tv_sec, mean_time.tv_nsec, \
		PASTE(_summary_type, _stats).PASTE(_stat_type, _max).tv_sec, PASTE(_summary_type, _stats).PASTE(_stat_type, _max).tv_nsec); \
} while (0)

#define __output_summary_stats(_summary_type, dir_path, garbage_args...) do { \
	struct timespec now; \
	clock_gettime(CLOCK_REALTIME, &now); \
	if (dir_path) \
		output("%lu.%09lu directory summary for \"%s\":\n", now.tv_sec, now.tv_nsec, (char *)dir_path); \
	else \
		output("%lu.%09lu overall summary\n", now.tv_sec, now.tv_nsec); \
\
	__output_getdents_summary_stat(_summary_type); \
	__output_one_summary_stat(_summary_type, INDIR(STAT_SYSCALL_NAME)); \
	__output_one_summary_stat(_summary_type, openat); \
	__output_one_summary_stat(_summary_type, close); \
} while (0)


#define __new_output_getdents_summary_stat(_stats) do { \
	struct timespec mean_time; \
\
	mean_time = mean_ts(_stats->getdents_elapsed, _stats->getdents_call_count); \
	output("    getdents - calls: %lu, elapsed: %lu.%09lu, mean: %lu.%09lu, max: %lu.%09lu, dirent count: %lu\n", \
		_stats->getdents_call_count, _stats->getdents_elapsed.tv_sec, _stats->getdents_elapsed.tv_nsec, \
		mean_time.tv_sec, mean_time.tv_nsec, \
		_stats->getdents_max.tv_sec, _stats->getdents_max.tv_nsec, \
		_stats->dirent_count);
} while (0)

#define __new_output_one_summary_stat(_summary_type, _stat_type) do { \
	struct timespec mean_time; \
\
	mean_time = mean_ts(PASTE(_summary_type, _stats).PASTE(_stat_type, _elapsed), PASTE(_summary_type, _stats).PASTE(_stat_type, _call_count)); \
	output("    %s - calls: %lu, elapsed: %lu.%09lu, mean: %lu.%09lu, max: %lu.%09lu\n", \
		STR(_stat_type), PASTE(_summary_type, _stats).PASTE(_stat_type, _call_count), \
		PASTE(_summary_type, _stats).PASTE(_stat_type, _elapsed).tv_sec, PASTE(_summary_type, _stats).PASTE(_stat_type, _elapsed).tv_nsec, \
		mean_time.tv_sec, mean_time.tv_nsec, \
		PASTE(_summary_type, _stats).PASTE(_stat_type, _max).tv_sec, PASTE(_summary_type, _stats).PASTE(_stat_type, _max).tv_nsec); \
} while (0)
#define __new_output_summary_stats(_summary_type, dir_path, garbage_args...) do { \
	struct stats_struct *these_stats = &PASTE(_summary_type, _stats); \
	struct timespec now; \
	clock_gettime(CLOCK_REALTIME, &now); \
	if (dir_path) \
		output("%lu.%09lu directory summary for \"%s\":\n", now.tv_sec, now.tv_nsec, (char *)dir_path); \
	else \
		output("%lu.%09lu overall summary\n", now.tv_sec, now.tv_nsec); \
\
	__new_output_getdents_summary_stat(_summary_type); \
	__new_output_one_summary_stat(_summary_type, INDIR(STAT_SYSCALL_NAME)); \
        __new_output_one_summary_stat(_summary_type, openat); \
        __new_output_one_summary_stat(_summary_type, close); \
\
} while (0)


/* an old version of output_summary_stats() */
#define foo(_type) do { \
	mean_time = mean_ts(PASTE(_type,_stats).getdents_elapsed, PASTE(_type, _stats).getdents_call_count); \
	output("    getdents - calls: %lu, elapsed: %lu.%09lu, mean: %lu.%09lu, max: %lu.%09lu, dirent count: %lu\n", \
		PASTE(_type, _stats).getdents_call_count, \
		PASTE(_type, _stats).getdents_elapsed.tv_sec, PASTE(_type, _stats).getdents_elapsed.tv_nsec, \
		mean_time.tv_sec, mean_time.tv_nsec, \
		PASTE(_type, _stats).getdents_max.tv_sec, PASTE(_type, _stats).getdents_max.tv_nsec, \
		PASTE(_type, _stats).dirent_count); \
\
	mean_time = mean_ts(PASTE(_type, _stats).PASTE_INDIR(STAT_SYSCALL_NAME, _elapsed), PASTE(_type, _stats).PASTE_INDIR(STAT_SYSCALL_NAME, _call_count)); \
	output("    %s - calls: %lu, elapsed: %lu.%09lu, mean: %lu.%09lu, max: %lu.%09lu\n", \
		stat_syscall_name, PASTE(_type, _stats).PASTE_INDIR(STAT_SYSCALL_NAME, _call_count), \
		PASTE(_type, _stats).PASTE_INDIR(STAT_SYSCALL_NAME, _elapsed).tv_sec, PASTE(_type, _stats).PASTE_INDIR(STAT_SYSCALL_NAME, _elapsed).tv_nsec, \
		mean_time.tv_sec, mean_time.tv_nsec, \
		PASTE(_type, _stats).PASTE_INDIR(STAT_SYSCALL_NAME, _max).tv_sec, PASTE(_type, _stats).PASTE_INDIR(STAT_SYSCALL_NAME, _max).tv_nsec); \
	mean_time = mean_ts(PASTE(_type, _stats).openat_elapsed, PASTE(_type, _stats).openat_call_count); \
	output("    openat - calls: %lu, elapsed: %lu.%09lu, mean: %lu.%09lu, max: %lu.%09lu\n", \
		PASTE(_type, _stats).openat_call_count, \
		PASTE(_type, _stats).openat_elapsed.tv_sec, PASTE(_type, _stats).openat_elapsed.tv_nsec, \
		mean_time.tv_sec, mean_time.tv_nsec, \
		PASTE(_type, _stats).openat_max.tv_sec, PASTE(_type, _stats).openat_max.tv_nsec); \
\
	mean_time = mean_ts(PASTE(_type, _stats).close_elapsed, PASTE(_type, _stats).close_call_count); \
	output("    close - calls: %lu, elapsed: %lu.%09lu, mean: %lu.%09lu, max: %lu.%09lu\n", \
		PASTE(_type, _stats).close_call_count, \
		PASTE(_type, _stats).close_elapsed.tv_sec, PASTE(_type, _stats).close_elapsed.tv_nsec, \
		mean_time.tv_sec, mean_time.tv_nsec, \
		PASTE(_type, _stats).close_max.tv_sec, PASTE(_type, _stats).close_max.tv_nsec); \
} while (0)




#define output_summary_stats(args...)  __output_summary_stats(args, NULL, NULL);

#define ts_lt(_ts1, _ts2) ((_ts1.tv_sec < _ts2.tv_sec || (_ts1.tv_sec == _ts2.tv_sec && _ts1.tv_nsec < _ts2.tv_nsec)))
#define ts_le(_ts1, _ts2) ((_ts1.tv_sec < _ts2.tv_sec || (_ts1.tv_sec == _ts2.tv_sec && _ts1.tv_nsec <= _ts2.tv_nsec)))
#define ts_eq(_ts1, _ts2) (_ts1.tv_sec == _ts2.tv_sec && _ts1.tv_nsec == _ts2.tv_nsec)
#define ts_ge(_ts1, _ts2) ((_ts1.tv_sec > _ts2.tv_sec || (_ts1.tv_sec == _ts2.tv_sec && _ts1.tv_nsec >= _ts2.tv_nsec)))
#define ts_gt(_ts1, _ts2) ((_ts1.tv_sec > _ts2.tv_sec || (_ts1.tv_sec == _ts2.tv_sec && _ts1.tv_nsec > _ts2.tv_nsec)))
#define normalize_ts(_ts) do { \
	while (_ts.tv_nsec < 0) { \
		_ts.tv_sec--; \
		_ts.tv_nsec += NSEC; \
	} \
	while (_ts.tv_nsec >= NSEC) { \
		_ts.tv_sec++; \
		_ts.tv_nsec -= NSEC; \
	} \
} while (0)


void handle_interrupt(int signum) {
	struct timespec now;

	clock_gettime(CLOCK_REALTIME, &now);
	output("%lu.%09lu interrupted\n", now.tv_sec, now.tv_nsec);
	interrupted = true;
}

static struct timespec ts_elapsed(const struct timespec ts1, const struct timespec ts2) {
	struct timespec ret;

//	if (ts1.tv_sec > ts2.tv_sec ||
//		(ts1.tv_sec == ts2.tv_sec && ts1.tv_nsec >= ts2.tv_nsec)) {
	if (ts_gt(ts1, ts2)) {
		ret.tv_sec = ts1.tv_sec - ts2.tv_sec;
		ret.tv_nsec = ts1.tv_nsec - ts2.tv_nsec;
	} else {
		ret.tv_sec = ts2.tv_sec - ts1.tv_sec;
		ret.tv_nsec = ts2.tv_nsec - ts1.tv_nsec;
	}

	normalize_ts(ret);
/*
	while (ret.tv_nsec < 0) {
		ret.tv_sec--;
		ret.tv_nsec += NSEC;
	}
	while (ret.tv_nsec >= NSEC) {
		ret.tv_sec++;
		ret.tv_nsec -= NSEC;
	}
*/
	return ret;
}

struct timespec add_ts(const struct timespec ts1, struct timespec ts2) {
	struct timespec ret;

	ret.tv_sec = ts1.tv_sec + ts2.tv_sec;
	ret.tv_nsec = ts1.tv_nsec + ts2.tv_nsec;

	normalize_ts(ret);
	return ret;
}

struct timespec mean_ts(struct timespec elapsed, uint64_t count) {
//	uint64_t nsec = (elapsed.tv_sec * NSEC) + elapsed.tv_nsec + (count - 1); // for rounding up
	uint64_t nsec = (elapsed.tv_sec * NSEC) + elapsed.tv_nsec; // for rounding down
	struct timespec ret;

	if (count == 0)
		ret.tv_sec = ret.tv_nsec = 0;
	else {
		nsec /= count;

		ret.tv_sec = nsec / NSEC;
		ret.tv_nsec = nsec % NSEC;
	}
	return ret;
}

int recurse_dir(int dfd, const char *dfd_path) {
	struct linux_dirent64 *de;
	struct stats_struct subdir_stats = { 0 };
	char *getdents_buf = NULL, *new_path = NULL, *bpos;
	uint64_t nread;

	new_path = malloc(PATH_MAX);
	getdents_buf = malloc(GETDENTS_BUFSIZE);
	while (42) {
		DEFINE_STOPWATCH(getdents);

		STOPWATCH_START(getdents);
		nread = syscall(SYS_getdents64, dfd, getdents_buf, GETDENTS_BUFSIZE);
		STOPWATCH_STOP(getdents);

		if (interrupted)
			goto out_interrupted;

		if (nread < 0)
			output("%lu.%09lu getdents(%d<%s>, %llu) = %lu (%m) <%lu.%09lu>\n",
				STOPWATCH_READ_START(getdents).tv_sec, STOPWATCH_READ_START(getdents).tv_nsec,
				dfd, dfd_path, GETDENTS_BUFSIZE, nread,
				STOPWATCH_READ_ELAPSED(getdents).tv_sec, STOPWATCH_READ_ELAPSED(getdents).tv_nsec);
		else
			output("%lu.%09lu getdents(%d<%s>, %llu) = %lu <%lu.%09lu>\n",
				STOPWATCH_READ_START(getdents).tv_sec, STOPWATCH_READ_START(getdents).tv_nsec,
				dfd, dfd_path, GETDENTS_BUFSIZE, nread,
				STOPWATCH_READ_ELAPSED(getdents).tv_sec, STOPWATCH_READ_ELAPSED(getdents).tv_nsec);

		incr_subdir_stats(getdents);

		if (nread == -1)
			exit_fail("getdents call failed");
		if (nread == 0)
			break;
		bpos = getdents_buf;
		while (bpos < getdents_buf + nread) {
			subdir_stats.dirent_count++;

			de = (struct linux_dirent64 *)bpos;
			bpos += de->d_reclen;

			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;

			{ // call fstatat()/statx() on the file & add times, ala 'ls -l' or 'du'
				union {
					struct stat st;
					struct statx stx;
				} statbuf;
				DEFINE_STOPWATCH(STAT_SYSCALL_NAME);

				STOPWATCH_START(STAT_SYSCALL_NAME);
				STAT_SYSCALL(dfd, de->d_name, &statbuf);
				STOPWATCH_STOP(STAT_SYSCALL_NAME);

				if (interrupted)
					goto out_interrupted;

				output("%lu.%09lu %s(%d<%s>, \"%s\") - <%lu.%09lu>\n",
					STOPWATCH_READ_START(STAT_SYSCALL_NAME).tv_sec, STOPWATCH_READ_START(STAT_SYSCALL_NAME).tv_nsec,
					stat_syscall_name, dfd, dfd_path, de->d_name,
					STOPWATCH_READ_ELAPSED(STAT_SYSCALL_NAME).tv_sec, STOPWATCH_READ_ELAPSED(STAT_SYSCALL_NAME).tv_nsec);
				incr_subdir_stats(STAT_SYSCALL_NAME);
			}

			switch (de->d_type) {
				case DT_DIR: {
					DEFINE_STOPWATCH(openat);
					int new_dfd;

					snprintf(new_path, PATH_MAX - 1, "%s/%s", dfd_path, de->d_name);

					STOPWATCH_START(openat);
					new_dfd = openat(dfd, de->d_name, O_DIRECTORY|O_RDONLY);
					STOPWATCH_STOP(openat);

					if (interrupted) {
						if (new_dfd >= 0)
							close(new_dfd);
						goto out_interrupted;
					}
					if (new_dfd < 0) {
						output("%lu.%09lu openat(\"%s\") = %d (%m) - <%lu.%09lu>\n",
							STOPWATCH_READ_START(openat).tv_sec, STOPWATCH_READ_START(openat).tv_nsec,
							new_path, new_dfd,
							STOPWATCH_READ_ELAPSED(openat).tv_sec, STOPWATCH_READ_ELAPSED(openat).tv_nsec);
						incr_subdir_stats(openat);
					} else {
						output("%lu.%09lu openat(\"%s\") = %d - <%lu.%09lu>\n",
							STOPWATCH_READ_START(openat).tv_sec, STOPWATCH_READ_START(openat).tv_nsec,
							new_path, new_dfd,
							STOPWATCH_READ_ELAPSED(openat).tv_sec, STOPWATCH_READ_ELAPSED(openat).tv_nsec);
						incr_subdir_stats(openat);

						recurse_dir(new_dfd, new_path);

						if (interrupted) {
							close(new_dfd);
							goto out_interrupted;
						}

						DEFINE_STOPWATCH(close);
						STOPWATCH_START(close);
						close(new_dfd);
						STOPWATCH_STOP(close);
						output("%lu.%09lu close(%d<%s>) - <%lu.%09lu>\n",
							STOPWATCH_READ_START(close).tv_sec, STOPWATCH_READ_START(close).tv_nsec,
							new_dfd, new_path,
							STOPWATCH_READ_ELAPSED(close).tv_sec, STOPWATCH_READ_ELAPSED(close).tv_nsec);
						incr_subdir_stats(close);
					}
				} ; break;
				case DT_UNKNOWN:
					output("Unknown directory entry type for '%s/%s'\n",
						dfd_path, de->d_name);
					break;
				default:
					break;
			}
			if (interrupted)
				goto out_interrupted;
		}
		// TODO: something with subdir_stats.dirent_count - last_dirent_count
		if (interrupted)
			goto out_interrupted;
	}

out_interrupted:
	// propagate subdir stats to overall
	incr_overall_stats(getdents);
	incr_overall_stats(STAT_SYSCALL_NAME);
	incr_overall_stats(openat);
	incr_overall_stats(close);

	output_summary_stats(subdir, dfd_path);

	if (getdents_buf)
		free(getdents_buf);
	if (new_path)
		free(new_path);

	return EXIT_SUCCESS;
}

int start_recursing(char *path) {
	char *actual_path = NULL;
	int dfd, ret = EXIT_FAILURE;

	if (!path || path[0] == '\0')
		actual_path = get_current_dir_name();
	else if (path[0] == '/')
		actual_path = strdup(path);
	else
		actual_path = realpath(path, NULL);

	output("crawling '%s'\n", actual_path);
	if ((dfd = openat(AT_FDCWD, actual_path, O_DIRECTORY|O_RDONLY)) < 0)
		output("could not open '%s' ('%s'): %m\n", path, actual_path);
	else
		ret = recurse_dir(dfd, actual_path);

	if (actual_path)
		free(actual_path);
	return ret;
}


int main(int argc, char *argv[]) {
	struct sigaction sa;
	DEFINE_STOPWATCH(runtime);

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &handle_interrupt;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	STOPWATCH_START(runtime);
	memset(&overall_stats, 0, sizeof(overall_stats));
	if (argc > 1) {
		int i;
		for (i = 1 ; i < argc ; i++) {
			start_recursing(argv[i]);
			if (interrupted)
				break;
		}
	} else
		start_recursing(".");
	STOPWATCH_STOP(runtime);

	output("******************************\n");
	output("exiting...  runtime: %lu.%09lu\n", STOPWATCH_READ_ELAPSED(runtime).tv_sec, STOPWATCH_READ_ELAPSED(runtime).tv_nsec);


	output_summary_stats(overall);

	return EXIT_SUCCESS;
}
