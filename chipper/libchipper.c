/*
	Frank Sorenson <sorenson@redhat.com>
	Red Hat, 2017

	chipper - a library to implement rotating logs

	usage: compile to object file or library, use with 'mulch'


*/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include "libchipper.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>
#include <errno.h>
#include <syscall.h>
#include <dlfcn.h>

#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <execinfo.h>
#include <stdbool.h>

#define ___STR(x...)    #x
#define __STR(x...)     ___STR(x)
#define __XSTR(s)       __STR(s)

#define FORMAT_PRINTF_ATTRIB(format_idx, arg_idx) \
	__attribute__(( format(printf, format_idx, arg_idx) ))

#if USE_INDIRECTS
#define FUNC_SECTION		__STR(LIBNAME)
#define FUNC_SECTION_INTERNAL	FUNC_SECTION
#define FUNC_SECTION_ATTRIB_STRING	FUNC_SECTION ",\"awx\"#"
#define FUNC_SECTION_INTERNAL_ATTRIB_STRING	FUNC_SECTION_INTERNAL ",\"awx\"#"

#define FUNC_SECTION_ATTRIBS \
	__attribute__((section(FUNC_SECTION_ATTRIB_STRING), used, aligned(8), noinline))

#define FUNC_SECTION_INLINE_ATTRIBS \
	__attribute__((section(FUNC_SECTION_ATTRIB_STRING), used, aligned(8)))
#define FUNC_SECTION_INTERNAL_ATTRIBS \
	__attribute__((section(FUNC_SECTION_INTERNAL_ATTRIB_STRING), used, aligned(8), noinline))
#define FUNC_SECTION_INTERNAL_INLINE_ATTRIBS \
	__attribute__((section(FUNC_SECTION_INTERNAL_ATTRIB_STRING), used, aligned(8)))
#else /* don't use indirects */
#define FUNC_SECTION
#define FUNC_SECTION_INTERNAL FUNC_SECTION
#define FUNC_SECTION_ATTRIB_STRING
#define FUNC_SECTION_INTERNAL_ATTRIB_STRING
#define FUNC_SECTION_ATTRIBS
#define FUNC_SECTION_INLINE_ATTRIBS
#define FUNC_SECTION_INTERNAL_ATTRIBS
#define FUNC_SECTION_INTERNAL_INLINE_ATTRIBS
#endif



#define VARS_SECTION		__STR(LIBNAME)
#define VARS_SECTION_INTERNAL	VARS_SECTION
//#define FUNC_SECTION_INTERNAL	__STR(__PASTE(LIBNAME, _internal))
//#define VARS_SECTION_INTERNAL	__STR(__PASTE(LIBNAME, _internal))

#define VARS_SECTION_ATTRIB_STRING	VARS_SECTION ",\"awx\",@progbits#"
#define VARS_SECTION_INTERNAL_ATTRIB_STRING	VARS_SECTION_INTERNAL ",\"awx\",@progbits#"
#define VARS_SECTION_ATTRIBS \
	__attribute__((section(VARS_SECTION_ATTRIB_STRING), used, aligned(8), nocommon))


#if __x86_64__
#define get_rip() ({ uint64_t ip; __asm__("leaq (%%rip), %0;": "=r"(ip)); ip; })
#endif

//#define typedefof(func) __PASTE3(LIBNAME,func,_func_t)
//#define typedef_func_sym(func) typedef typeof(func) typedefof(func)

struct chipper_internal;

typedef void (*chipper_rotate_func_t)(struct chipper_internal *self);
typedef void (*chipper_close_log_func_t)(struct chipper_internal *self);
typedef void (*chipper_compress_func_t)(struct chipper_internal *self, const char *logfile, int wait);
typedef ssize_t (*__chipvprintf_out_func_t)(struct chipper_internal *self, const char *fmt, va_list ap);

static int __chipper_check_rotate(struct chipper_internal *self);

struct chipper_internal {
	union {
		struct chipper public;
		struct chipper;
	};
	struct chipper_internal *me;
	uint64_t chipper_instance;

	uint64_t my_offset;

	int output_fd;
	int log_dir_fd;
	char *log_dir;

	bool timestamp;
	bool quiet;
	enum chipper_tstamp_precision timestamp_precision;
	char *timestamp_format;

	uint64_t log_rotate_size;
	uint64_t total_bytes;
	uint64_t log_bytes;
	int log_filenum;

	char *log_basename;
	char *log_pattern;
	char *log_filename; /* current */
	char *compressed_log;
	bool overwrite_log;

	pid_t tid;

	void *start;
	void *stop;
	uint64_t size;
};
typedef struct chipper_internal chipper_internal_t;

static chipper_internal_t VARS_SECTION_ATTRIBS self;


#define typedefof(func) __PASTE(func,_func_t)
#define typedef_func_sym(func) typedef typeof(func) typedefof(func)
#define func_ptr_var_name(func) __PASTE(func,_ptr)
#define func_ptr_var_set(func) typedefof(func) VARS_SECTION_ATTRIBS *func_ptr_var_name(func) = func
#define func_make_func_ptr(func) \
	typedef_func_sym(func); \
	func_ptr_var_set(func)


extern ssize_t __chipper_set_rotate_size(struct chipper_internal *self, ssize_t size);
func_make_func_ptr(__chipper_set_rotate_size);

extern int __chipwrite(struct chipper_internal *self, const void *buf, ssize_t count);
func_make_func_ptr(__chipwrite);

extern int __chipprintf(struct chipper_internal *self, const char *fmt, va_list ap);
func_make_func_ptr(__chipprintf);

extern void __chipper_exit(struct chipper_internal *self);
func_make_func_ptr(__chipper_exit);


#define unlikely(x)     __builtin_expect((x),0)

#define NSEC_TO_MSEC(l) (l / 1000000ULL)
#define NSEC_TO_USEC(l) (l / 1000ULL)

#define BUF_SIZE (32ULL * KiB)

#define DEFAULT_LOG_PATTERN "log_%d.%d"

#define CHIPPER_MAGIC (uint32_t)(('P' << 24) + ('I' << 16) + ('H' << 8) + ('C'))
#define CHIPPER_TSTAMP_FMT "%F %T"

void print_bt(void) {
  void *array[10];
  size_t size;
  char **strings;
  size_t i;

  size = backtrace (array, 10);
  strings = backtrace_symbols (array, size);

  printf ("Obtained %zd stack frames.\n", size);

  for (i = 0; i < size; i++)
     printf ("%s\n", strings[i]);

  free (strings);
}

static void FUNC_SECTION_INTERNAL_ATTRIBS __attribute__((constructor)) __chipper_init_internal(void);
int FUNC_SECTION_INLINE_ATTRIBS valid_chip(struct chipper_internal *self);

static inline pid_t gettid(void) {
	return (pid_t)syscall(SYS_gettid);
}

int FUNC_SECTION_INLINE_ATTRIBS valid_chip(struct chipper_internal *self) {
	if (self->magic == CHIPPER_MAGIC)
		return 1;
	return 0;
}
static ssize_t FUNC_SECTION_INTERNAL_ATTRIBS __chipvprintf_out(struct chipper_internal *self, const char *fmt, va_list ap) {
	ssize_t len;

	len = vdprintf(self->output_fd, fmt, ap);
	self->log_bytes += len;
	self->total_bytes += len;
	return len;
}
static ssize_t FUNC_SECTION_INTERNAL_ATTRIBS __chipprintf_out(struct chipper_internal *self, const char *fmt, ...) {
	va_list ap;
	ssize_t len;

	va_start(ap, fmt);
	len = __chipvprintf_out(self, fmt, ap);
	va_end(ap);

	return len;
}

ssize_t chipper_fill_tstamp_buf(char *tstamp_buf, int tstamp_buf_len, enum chipper_tstamp_precision tsp) {
	struct timespec ts;
	struct tm tm_info;
	ssize_t len;

	clock_gettime(CLOCK_REALTIME, &ts);
	if (tsp == chipper_tstamp_precision_unix)
		return snprintf(tstamp_buf, tstamp_buf_len, "%lu", ts.tv_sec);
	else if (tsp == chipper_tstamp_precision_unix_ns)
		return snprintf(tstamp_buf, tstamp_buf_len, "%lu.%09ld", ts.tv_sec, ts.tv_nsec);

	localtime_r(&ts.tv_sec, &tm_info);
	len = strftime(tstamp_buf, tstamp_buf_len, CHIPPER_TSTAMP_FMT, &tm_info);
	switch (tsp) {
		case chipper_tstamp_precision_ms:
			len += snprintf(tstamp_buf + len, sizeof(tstamp_buf) - len, ".%03lld", NSEC_TO_MSEC(ts.tv_nsec));
			break;
		case chipper_tstamp_precision_us:
			len += snprintf(tstamp_buf + len, sizeof(tstamp_buf) - len, ".%06lld", NSEC_TO_USEC(ts.tv_nsec));
			break;
		case chipper_tstamp_precision_ns:
			len += snprintf(tstamp_buf + len, sizeof(tstamp_buf) - len, ".%09ld", ts.tv_nsec);
			break;
		default:
			break;
	}
	return len;
}


static ssize_t FUNC_SECTION_INTERNAL_ATTRIBS __chipprintf_tstamp(struct chipper_internal *self) {
	char tstamp_buf[40] = { 0 };
	ssize_t len, ret;

	len = chipper_fill_tstamp_buf(tstamp_buf, sizeof(tstamp_buf), self->timestamp_precision);

	ret = __chipprintf_out(self, "\n%s: ", tstamp_buf);
	if (len != ret) {
		; /* error */
	}
	return ret;
}
ssize_t chipper_output_tstamp(int fd, enum chipper_tstamp_precision tsp) {
	char tstamp_buf[40] = { 0 };
	ssize_t len;

	len = chipper_fill_tstamp_buf(tstamp_buf, sizeof(tstamp_buf), tsp);
	tstamp_buf[len++] = ':';
	tstamp_buf[len++] = ' ';
	tstamp_buf[len] = '\0';
	return write(fd, tstamp_buf, len);
}


int FUNC_SECTION_INTERNAL_ATTRIBS __chipprintf(struct chipper_internal *self, const char *fmt, va_list ap) {
	ssize_t len = 0;

	if (self->timestamp)
		len += __chipprintf_tstamp(self);

	len += __chipvprintf_out(self, fmt, ap);

	__chipper_check_rotate(self);

	return len;
}

/* stub to call the real chipprintf with the object pointer */
int FUNC_SECTION_ATTRIBS FORMAT_PRINTF_ATTRIB(1, 2) chipprintf_old(const char *fmt, ...) {
	va_list ap;
	ssize_t len = 0;

	va_start(ap, fmt);
	typeof(__chipprintf) *__chipprintf_ptr = &__chipprintf;
	len += __chipprintf_ptr(self.me, fmt, ap);
	va_end(ap);
	return len;
}

int FUNC_SECTION_ATTRIBS FORMAT_PRINTF_ATTRIB(1, 2) chipprintf(const char *fmt, ...) {
	va_list ap;
	ssize_t len = 0;

	va_start(ap, fmt);
	len += __chipprintf_ptr(self.me, fmt, ap);
	va_end(ap);
	return len;
}

int FUNC_SECTION_INTERNAL_ATTRIBS __chipwrite(struct chipper_internal *self, const void *buf, ssize_t count) {
	ssize_t len = 0;

	len = write(self->output_fd, buf, count);
	self->log_bytes += len;
	self->total_bytes += len;

	__chipper_check_rotate(self);

	return len;
}

extern ssize_t chipwrite(const void *buf, ssize_t count);
#if __x86_64__ && USE_INDIRECTS
__asm__(
	".section " __STR(LIBNAME) "\n\t"
	".globl chipwrite\n\t"
	".type chipwrite, @function\n"
"chipwrite:\n\t"
	"movq %rsi, %rdx\n\t"
	"movq %rdi, %rsi\n\t"
	"lea __start_" __STR(LIBNAME) "(%rip), %rdi\n\t" /* the address of _THIS_ chipper */

	"jmp *__chipwrite_ptr\n\t"
//	"movq __chipwrite_ptr, %rax\n\t"
//	"jmp *%rax\n\t"

	".size chipwrite, . - chipwrite\n\t"

);
#else

#pragma GCC push_options
#pragma GCC optimize ("O3")
ssize_t FUNC_SECTION_ATTRIBS chipwrite(const void *buf, ssize_t count) {
	return __chipwrite_ptr(self.me, buf, count);
}
#pragma GCC pop_options

#endif


int FUNC_SECTION_ATTRIBS mkdir_r(const char *path) {
	char *parent_path;
	struct stat st;
	char *tmp;
	int ret = 0;
	int lim = 3;

re_stat:
	if (lim-- <= 0)
		return -ret;
	if (stat(path, &st) == -1) {
		if (errno == ENOTDIR)
			return -ENOTDIR;

		if (errno == ENOENT) {
			tmp = strdup(path);
			parent_path = dirname(tmp);

			ret = mkdir_r(parent_path);
			free(tmp);
			if (ret < 0)
				return ret;
			ret = mkdir(path, 0755);
			return -ret;
		}
		goto re_stat;
	}
	if (! S_ISDIR(st.st_mode))
		return -ENOTDIR;

	return 0;
}

static void FUNC_SECTION_INTERNAL_ATTRIBS __chipper_open_log(struct chipper_internal *self) {
	asprintf(&self->log_filename, self->log_pattern, self->chipper_instance, self->log_filenum);

	if ((self->output_fd = openat(self->log_dir_fd, self->log_filename, O_CREAT | O_TRUNC | O_WRONLY, 0666)) < 0) {
		dprintf(STDERR_FILENO, "ERROR: unable to open logfile '%s/%s': %m\n",
			self->log_dir, self->log_filename);
		exit(EXIT_FAILURE);
	}
}
static void FUNC_SECTION_INTERNAL_ATTRIBS __chipper_close_log(struct chipper_internal *self) {
	close(self->output_fd);
}

typedef enum redir_fd_enum { redir_fd_in, redir_fd_out_trunc, redir_fd_out_append } redir_fd_enum_t;
int redir_fd(int fd_to_replace, const char *redir_path, redir_fd_enum_t redir_type) {
	int new_fd;

	if (redir_type == redir_fd_in)
		new_fd = open(redir_path, O_RDONLY);
	else if (redir_type == redir_fd_out_trunc)
		new_fd = open(redir_path, O_CREAT|O_WRONLY|O_TRUNC, 0644);
	else if (redir_type == redir_fd_out_append)
		new_fd = open(redir_path, O_CREAT|O_WRONLY|O_APPEND, 0644);

	if (new_fd < 0)
		return -1;

	return dup2(new_fd, fd_to_replace);
}
pid_t run_as_child(char *const argv[], char *const env[], const char *stdin_file,
		const char *stdout_file, bool overwrite_out,
		const char *stderr_file, bool overwrite_err) {
	pid_t cpid = 0;

	cpid = fork();
	if (!cpid) {
		if (stdin_file)
			redir_fd(STDIN_FILENO, stdin_file, redir_fd_in);
		if (stdout_file)
			redir_fd(STDOUT_FILENO, stdout_file,
				overwrite_out ? redir_fd_out_trunc : redir_fd_out_append);
		if (stderr_file)
			redir_fd(STDERR_FILENO, stderr_file,
				overwrite_err ? redir_fd_out_trunc : redir_fd_out_append);
		execve(argv[0], argv, env);
		exit(EXIT_FAILURE);
	}
	return cpid;
}
static ssize_t FUNC_SECTION_INTERNAL_ATTRIBS __chipper_cat_file(const char *src, const char *dest) {
	ssize_t read_len, write_len;
	ssize_t total_len = 0;
	int src_fd, dest_fd;
	char *buf;
	int ret = 0;

	buf = malloc(BUF_SIZE);
	if ((src_fd = open(src, O_RDONLY)) < 0) {
		ret = -errno;
		goto out_free;
	}
	if ((dest_fd = open(dest, O_CREAT|O_WRONLY|O_APPEND, 0644)) < 0) {
		ret = -errno;
		goto out_close_src;
	}
	while ((read_len = read(src_fd, buf, BUF_SIZE))) {
		if (read_len == -1) {
			ret = -errno;
			goto out_close_dest;
		}
		write_len = write(dest_fd, buf, read_len);
		if (write_len == -1) {
			ret = -errno;
			goto out_close_dest;
		}
		total_len += write_len;
	}

out_close_dest:
	close(dest_fd);
out_close_src:
	close(src_fd);
out_free:
	free(buf);

	return ret;
}

static void FUNC_SECTION_INTERNAL_ATTRIBS __chipper_compress_log(struct chipper_internal *self, const char *old_log, int wait) {
	(void)wait; /* do it all synchronously for now...  need to create a work queue to do this right */
	pid_t cpid = 0;

	cpid = fork();
	if (!cpid) { /* child process... exec the compressor */
//#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
		char *argv[] = { "/usr/bin/gzip", "-f", NULL, NULL, NULL, NULL };
//#pragma GCC diagnostic warning "-Wdiscarded-qualifiers"
		char *env[] = { NULL };
		char *compressed_old_log;
		pid_t cpid2;

		argv[2] = (char *)old_log;

		cpid2 = run_as_child(argv, env, "/dev/null",
			"/dev/null", false,
			"/dev/null", false);
		waitpid(cpid2, NULL, 0);

		asprintf(&compressed_old_log, "%s.gz", old_log);
		__chipper_cat_file(compressed_old_log, self->compressed_log);
		unlink(compressed_old_log);
		free(compressed_old_log);

		exit(EXIT_SUCCESS);
	}
//	if (wait)
		waitpid(cpid, NULL, 0); /* could use better^H^H^H^H^H^Hsome error handling, etc. */
}
static void FUNC_SECTION_INTERNAL_ATTRIBS __chipper_rotate_log(struct chipper_internal *self) {
	char *old_log;

	asprintf(&old_log, "%s/%s", self->log_dir, self->log_filename);
	__chipper_close_log(self);
	self->log_filenum++;
	free(self->log_filename);

	__chipper_compress_log(self, old_log, 0);
	free(old_log);
	__chipper_open_log(self);
}

static int FUNC_SECTION_INTERNAL_INLINE_ATTRIBS __chipper_check_rotate(struct chipper_internal *self) {
	if (self->log_bytes >= self->log_rotate_size) {
		__chipper_rotate_log(self);
		return 1;
	}
	return 0;
}

int FUNC_SECTION_ATTRIBS chipper_set_tstamp_onoff(int set) {
	return self.me->timestamp = set;
}
bool FUNC_SECTION_ATTRIBS chipper_set_quiet_onoff(bool set) {
	return self.me->quiet = set;
}
enum chipper_tstamp_precision FUNC_SECTION_ATTRIBS chipper_set_tstamp_precision(enum chipper_tstamp_precision tsp) {
	return self.me->timestamp_precision = tsp;
}
static int FUNC_SECTION_INTERNAL_ATTRIBS __chipper_set_tstamp_format(struct chipper_internal *self, const char *fmt) {
	if (self->timestamp_format)
		free(self->timestamp_format);
	self->timestamp_format = strdup(fmt);
	return 0;
}
ssize_t FUNC_SECTION_ATTRIBS chipper_get_total_bytes(void) {
	return self.me->total_bytes;
}
ssize_t FUNC_SECTION_INTERNAL_ATTRIBS __chipper_set_rotate_size(struct chipper_internal *self, ssize_t size) {
	if (size < (typeof(size))MIN_LOG_ROTATE_SIZE)
		size = MIN_LOG_ROTATE_SIZE;
	self->log_rotate_size = size;
	__chipper_check_rotate(self);
	return self->log_rotate_size;
}

#if __x86_64__ && USE_INDIRECTS
extern ssize_t chipper_set_rotate_size(ssize_t size);
__asm__(
	".section " __STR(LIBNAME) "\n\t"
	".globl chipper_set_rotate_size\n\t"
	".type chipper_set_rotate_size, @function\n"
"chipper_set_rotate_size:\n\t"
	"movq %rdi, %rsi\n\t"
	"lea __start_" __STR(LIBNAME) "(%rip), %rdi\n\t"
	"jmp *__chipper_set_rotate_size_ptr\n\t"
	".size chipper_set_rotate_size, . - chipper_set_rotate_size\n\t"
);
#else

#pragma GCC push_options
#pragma GCC optimize ("O3")
ssize_t FUNC_SECTION_ATTRIBS chipper_set_rotate_size(ssize_t size) {
	return __chipper_set_rotate_size_ptr(self.me, size);
}
#pragma GCC pop_options

#endif


static int FUNC_SECTION_INTERNAL_ATTRIBS __chipper_create_logdir(const char *log_dir) {
	if (mkdir_r(log_dir) < 0) {
		dprintf(STDERR_FILENO, "unable to create log directory '%s'\n", log_dir);
		return -ENOTDIR;
	}
	return 0;
}
static int FUNC_SECTION_INTERNAL_ATTRIBS __chipper_open_logdir(struct chipper_internal *self) {
	if ((self->log_dir_fd = open(self->log_dir, O_RDONLY|O_DIRECTORY)) < 0) {
		dprintf(STDERR_FILENO, "ERROR: unable to open log directory '%s': %m\n",
			self->log_dir);
		return -errno;
	}
	return 0;
}
static int FUNC_SECTION_INTERNAL_ATTRIBS __chipper_set_logdir(struct chipper_internal *self, const char *log_dir) {
	char *tmp = NULL;
	int ret;

	if (self->log_dir_fd >= 0) {
		/* hmm. what to do if we change mid-stream */
		dprintf(STDERR_FILENO, "unable to change log directory\n");
		return -EBUSY;
	}

	if ((ret = __chipper_create_logdir(log_dir)))
		return ret;
	tmp = self->log_dir;
	self->log_dir = strdup(log_dir);
	if (tmp)
		free(tmp);

	return 0;
}
static int FUNC_SECTION_INTERNAL_ATTRIBS __chipper_set_compressed_log(struct chipper_internal *self, const char *compressed_log) {
	int open_flags = O_RDWR | O_CREAT;
	int ret = 0;
	int fd;

	self->compressed_log = strdup(compressed_log);
	if (self->overwrite_log)
		open_flags |= O_TRUNC;
	else
		open_flags |= O_APPEND;

	if ((fd = open(self->compressed_log, O_RDWR|O_CREAT|O_TRUNC, 0644)) < 0) {
		dprintf(STDERR_FILENO, "Error while opening output logfile '%s': %m\n",
			self->compressed_log);
		ret = errno;
		free(self->compressed_log);
		self->compressed_log = NULL;
	} else
		close(fd);
	return ret;
}

static chipper_t *FUNC_SECTION_INTERNAL_ATTRIBS __chipper_init(struct chipper_internal *self, const char *compressed_log) {
	int ret;

//	if ((ret = __chipper_set_logdir(self, log_dir)))
//		return NULL;
	if ((ret = __chipper_set_compressed_log(self, compressed_log)))
		return NULL;
	if ((ret = __chipper_create_logdir(self->log_dir)))
		return NULL;
	if ((ret = __chipper_open_logdir(self)))
		return NULL;
	__chipper_open_log(self);
	return &self->public;
}

void FUNC_SECTION_INTERNAL_ATTRIBS __chipper_exit(struct chipper_internal *self) {
	char *old_log;

	asprintf(&old_log, "%s/%s", self->log_dir, self->log_filename);
	__chipper_close_log(self);

	free(self->log_filename);
	self->log_filename = NULL;

	free(self->timestamp_format);
	self->timestamp_format = NULL;

	if (! self->quiet)
		dprintf(STDERR_FILENO, "Please wait... compressing log\n");
	__chipper_compress_log(self, old_log, 1);
	free(old_log);

	free(self->log_pattern);
	self->log_pattern = NULL;

	close(self->log_dir_fd);
	self->log_dir_fd = -1;
	rmdir(self->log_dir);

	free(self->log_dir);
	self->log_dir = NULL;
}
/* stub to call the real chipper_exit */
extern void FUNC_SECTION_ATTRIBS chipper_exit(void);
#if __x86_64__ && USE_INDIRECTS
__asm__(
	".section " __STR(LIBNAME) "\n\t"
	".globl chipper_exit\n\t"
	".type chipper_exit, @function\n"
"chipper_exit:\n\t"
	"movq %rdi, %rsi\n\t"
	"lea __start_" __STR(LIBNAME) "(%rip), %rdi\n\t"
	"jmp *__chipper_exit_ptr\n\t"
	".size chipper_exit, . - chipper_exit\n\t"
);
#else
void FUNC_SECTION_ATTRIBS chipper_exit(void) {
	__chipper_exit_ptr(self.me);
}
#endif

#pragma GCC push_options
#pragma GCC optimize ("O3")
static void FUNC_SECTION_INTERNAL_ATTRIBS __chipper_fixup_offsets(void *new_base, uint64_t offset) {
	struct chipper_internal *new_self = new_base;

	new_self->my_offset = offset;
	new_self->start += offset;
	new_self->stop += offset;
#if USE_INDIRECTS
	new_self->chipprintf += offset;
	new_self->chipwrite += offset;
	new_self->set_tstamp_onoff += offset;
	new_self->set_quiet_onoff += offset;
	new_self->set_tstamp_precision += offset;

	new_self->get_total_bytes += offset;
	new_self->set_rotate_size += offset;
	new_self->exit += offset;
#else
	new_self->chipprintf = chipprintf;
	new_self->chipwrite = chipwrite;
	new_self->set_tstamp_onoff = chipper_set_tstamp_onoff;
	new_self->set_quiet_onoff = chipper_set_quiet_onoff;
	new_self->set_tstamp_precision = chipper_set_tstamp_precision;
	new_self->get_total_bytes = chipper_get_total_bytes;
	new_self->set_rotate_size = chipper_set_rotate_size;
	new_self->exit = chipper_exit;


#endif
	new_self->log_pattern = strdup(DEFAULT_LOG_PATTERN);
	new_self->timestamp_format = strdup(CHIPPER_TSTAMP_FMT);
	asprintf(&new_self->log_dir, DEFAULT_LOG_DIR, new_self->tid);
}
#pragma GCC pop_options

struct chipper *new_chipper(const char *output_file, uint32_t flags) {
	static struct chipper_internal *chipper_lib_base = (struct chipper_internal *)&__start_libchipper;
	struct chipper_internal *tmp;

#if USE_INDIRECTS

	ssize_t chipper_size = &__stop_libchipper - &__start_libchipper;
	uint64_t offset;
	static uint64_t chipper_instance = 0;

	posix_memalign((void *)&tmp, 4096, chipper_size);
	mprotect(tmp, chipper_size, PROT_READ|PROT_WRITE|PROT_EXEC);

	memcpy(tmp, &__start_libchipper, chipper_size);
	tmp->me = tmp;
	tmp->chipper_instance = chipper_instance++;

	offset = (uint64_t)tmp - (uint64_t)chipper_lib_base;
	__chipper_fixup_offsets(tmp, offset);
#else
	tmp = chipper_lib_base;
	tmp->me = tmp;
#endif

	/* take care of some flags */
	if ((flags & (CHIPPER_LOG_OVERWRITE | CHIPPER_LOG_APPEND)) == CHIPPER_LOG_OVERWRITE)
		tmp->overwrite_log = true;
	else /* default to append */
		tmp->overwrite_log = false;

	if (flags & CHIPPER_QUIET)
		tmp->quiet = true;

	if (! (flags & CHIPPER_TSTAMP_MASK))
		tmp->timestamp = false;
	if (tmp->timestamp) {
		tmp->timestamp_precision =
			chipper_tstamp_flag_precision(flags & CHIPPER_TSTAMP_MASK);
		if (tmp->timestamp_precision == chipper_tstamp_none)
			tmp->timestamp = false;
	}

	if (__chipper_init(tmp, output_file) == 0) {
		dprintf(STDERR_FILENO, "Unable to configure logging to '%s': %s\n", output_file, strerror(errno));
		tmp = NULL;
	} else if (! tmp->quiet)
		dprintf(STDERR_FILENO, "Initialized logging to '%s'\n", output_file);
	return (struct chipper *)tmp;
}


static void FUNC_SECTION_INTERNAL_ATTRIBS __attribute__((constructor)) __chipper_init_internal(void) {
	self.me = &self;
	self.magic = CHIPPER_MAGIC;

	self.start = (void *)&SECTION_START(LIBNAME);
	self.stop = (void *)&SECTION_STOP(LIBNAME);
	SECTION_SIZE(LIBNAME) = &SECTION_STOP(LIBNAME) - &SECTION_START(LIBNAME);
	self.size = (ssize_t)SECTION_SIZE(LIBNAME);

	/* point the functions */
	self.chipprintf = chipprintf;
	self.chipwrite = chipwrite;

	self.set_tstamp_onoff = chipper_set_tstamp_onoff;
	self.set_quiet_onoff = chipper_set_quiet_onoff;
	self.set_tstamp_precision = chipper_set_tstamp_precision;
	self.get_total_bytes = chipper_get_total_bytes;
	self.set_rotate_size = chipper_set_rotate_size;

	self.exit = chipper_exit;

	self.log_rotate_size = DEFAULT_LOG_ROTATE_SIZE; /* just set to avoid func side effects */
	self.log_pattern = strdup(DEFAULT_LOG_PATTERN);
	self.timestamp = true; /* just set to avoid func side effects */
	self.quiet = false;
	self.timestamp_precision = chipper_tstamp_precision_ns; /* just set to avoid func side effects */

	self.output_fd = -1;
	self.log_dir_fd = -1;
	self.tid = gettid();
	asprintf(&self.log_dir, DEFAULT_LOG_DIR, self.tid); /* *** *** */

	self.total_bytes = 0;
	self.log_bytes = 0;
	self.log_filenum = 0;

	self.log_filename = NULL;
}
uint64_t foo_bar_baz_var = 42;
//uint64_t SECTION_SIZE(LIBNAME) = SECTION_STOP(LIBNAME) - SECTION_START(LIBNAME);
uint64_t VARS_SECTION_ATTRIBS SECTION_SIZE(LIBNAME);
