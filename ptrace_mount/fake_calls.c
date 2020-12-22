#include "ptrace_mount.h"
#include "fake_calls.h"
//#include "hexdump.h"
//#include "misc.h"

#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <syscall.h>

#include <linux/memfd.h>
#include <sys/mman.h>
#include "ptrace_defs.h"

/* reads a null-terminated string from the ptraced process */
char *ptrace_get_str(pid_t cpid, unsigned long addr) {
	char *buf = malloc(4096);
	int allocated = 4096;
	unsigned long tmp;
	int read = 0;
	while (1) {
		if (read + sizeof(tmp) > allocated) {
			allocated *= 2;
			buf = realloc(buf, allocated);
		}
		tmp = ptrace(PTRACE_PEEKDATA, cpid, addr + read);
		if (errno != 0) {
			buf[read] = 0;
			break;
		}
		memcpy(buf + read, &tmp, sizeof(tmp));
		if (memchr(&tmp, 0, sizeof(tmp)) != NULL)
			break;
		read += sizeof(tmp);
	}
	return buf;
}
void *ptrace_read_bytes(pid_t cpid, unsigned long addr, void *buf, int len) {
	unsigned long tmp;
	int read = 0;

	for (read = 0 ; read < len ; read += sizeof(tmp)) {
		tmp = ptrace(PTRACE_PEEKDATA, cpid, addr + read);
		if (errno != 0) {
			output("error reading: %m\n");
		}
		memcpy(buf + read, &tmp, sizeof(tmp));
	}
	return buf;
}
void ptrace_write_bytes(pid_t cpid, unsigned long addr, void *buf, int len) {
	unsigned long tmp;
	int count = 0;

	for (count = 0 ; count < len ; count += sizeof(tmp)) {
		memcpy(&tmp, buf + count, sizeof(tmp));
//		tmp = *(unsigned long *)(buf + count);
		ptrace(PTRACE_POKEDATA, cpid, addr + count, tmp);
	}
}

#if 0
char *modify_path(char *path) {
	char *new_path = NULL;
//	int len = strlen(path);

	if (!strncmp(path, "/proc", 5)) {
		new_path = strdup(path + 1);
	} else if (!strncmp(path, "/etc", 4)) {
		new_path = strdup(path + 1);
	} else if (!strncmp(path, "/sys", 4)) {

		if (path_exists(path + 1))
			new_path = strdup(path + 1);
		else if (!strncmp(path, "/sys/dev/block", 14)) {
			asprintf(&new_path, "sys/block%s", path + 14);
		} else
			new_path = strdup(path + 1);
	} else if (!strncmp(path, "/dev", 4)) {
		new_path = strdup(path + 1);

	} // anything else to replace?
	if (new_path == NULL)
		new_path = strdup(path);
	return new_path;
}
#endif

#define try_output_str(_reg, _addr) do { \
        if (can_access(_addr)) { \
                char *_s = (char *)_addr; \
                output("reg '%s' (%p): reachable, string: '%s'\n", #_reg, _s, _s); \
                if (*((char *)_addr)) { \
                        output("reg '%s' (%p): reachable, string: '%s'\n", #_reg, (char *)_addr, (char *)_addr); \
                } \
                else \
                        output("reg '%s': reachable, but first character is null value: %02x\n", #_reg, *(char *)_addr); \
        } else \
                output("reg '%s': not reachable (%m)\n", #_reg); \
} while (0)


#define complete_syscall(_cpid) do { \
	int _status; \
	ptrace(PTRACE_SYSCALL, _cpid, NULL, NULL); \
	waitpid(_cpid, &_status, 0); \
	if (WIFEXITED(_status)) { \
		config.child_exited = true; \
		exit(EXIT_FAILURE); /* should we exit, or just return? */ \
	} \
} while (0)

off_t read_file(const char *path, char **buf) {
	struct stat st;
	int fd;

	if ((fd = open(path, O_RDONLY)) == -1) {
		output("unable to open file '%s': %m\n", path);
		exit(EXIT_FAILURE);
	}
	if ((fstat(fd, &st)) != 0) {
		output("failed to stat open file '%s': %m\n", path);;
		exit(EXIT_FAILURE);
	}
	*buf = malloc(st.st_size);
	read(fd, *buf, st.st_size);
	close(fd);
	return st.st_size;
}

int fake_calls_init() {

	return 0;
}
