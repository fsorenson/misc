#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <execinfo.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <regex.h>
#include <string.h>
#include <limits.h>
#include <syscall.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <linux/sched.h>
#include <errno.h>
#include <ctype.h>

#include <sys/reg.h>

#include <xfs/xfs.h>
#include <xfs/xfs_format.h>

#include "common.h"
#include "hexdump.h"

#include "/home/sorenson/RH/rhkernel_trees/rhel8/fs/xfs/libxfs/xfs_format.h"

struct xfs_info_struct {
	uint64_t fs_size; /* in bytes */
	uint64_t agsize; /* in filesystem blocks */
	uint32_t agcount;
	uint32_t block_size; /* in bytes */
	uint32_t inode_size /* in bytes */;

	uint32_t log_block_size;
	uint32_t log_size; /* in log blocks */
	char *devpath; /* path to the device or filesystem image */

	int fs_fd; /* fd of the open filesystem device or image */
	uint64_t fs_fd_pos; /* file position of the fd */

	int verbosity;

	int pidfd; /* PID file descriptor - filled out by clone */
	pid_t child_tid;
	pid_t parent_tid;

	bool child_exited;
} xfs_info = {
	.agsize = 268435455ULL,
	.agcount = 127ULL,
	.block_size = 4096ULL,
	.inode_size = 512ULL,
	.devpath = "../foo.img",

	.fs_fd = -1,

	.verbosity = 0,

	.pidfd = -1,
	.child_tid = 0,
	.parent_tid = 0,

	.child_exited = false,
};

#define SYSCALL_NUM(x) (x.orig_rax)
#define SYSCALL_REG_RET(x) (x.rax)

#define SYSCALL_ARG_0(x) (x.rdi)
#define SYSCALL_ARG_1(x) (x.rsi)
#define SYSCALL_ARG_2(x) (x.rdx)
#define SYSCALL_ARG_3(x) (x.r10)
#define SYSCALL_ARG_4(x) (x.r8)
#define SYSCALL_ARG_5(x) (x.r9)

#define catch_return(_cpid) do { \
        int _status; \
        ptrace(PTRACE_SYSCALL, _cpid, NULL, NULL); \
        waitpid(_cpid, &_status, 0); \
        if (WIFEXITED(_status)) \
                xfs_info.child_exited = true; \
} while (0)


#define POS_TO_AG(pos) ( pos / xfs_info.block_size / xfs_info.agsize )
#define POS_TO_DBLOCK(pos) ( pos / 512ULL )
#define POS_TO_FSBLOCK(pos) ( pos / xfs_info.block_size )
#define POS_TO_AG_BLOCK(pos) ( (pos / xfs_info.block_size) % xfs_info.agsize )
//#define POS_TO_AG_BLOCK_OFFSET(pos) ( (pos / xfs_info.agsize) % xfs_info.block_size )
#define POS_TO_AG_BLOCK_OFFSET(pos) ( pos % xfs_info.block_size )

#define POS_TO_INODE_NUM(pos) ( (pos / xfs_info.inode_size) + (POS_TO_AG(pos) * 8) )


#define can_access(_addr) ({ \
	unsigned char vector[1]; \
	int ret = mincore((void *)(_addr & ~(4096 - 1)), 4096, vector); \
	if (ret == 0) \
		output("mincore of 0x%llx was successful...  result: %d\n", _addr, (int)ret); \
	else \
		output("mincore of 0x%llx returned %d: %m\n", _addr, ret); \
	(ret == 0); \
})

uint64_t read_uint64_t(pid_t child, unsigned long addr) {
	uint64_t val;

	val = ptrace(PTRACE_PEEKDATA, child, addr);
	if (errno != 0)
		return val;
	return 0;
}

char *read_bytes(pid_t cpid, unsigned long addr, unsigned long len) { char *ret = malloc(len);
	unsigned long read = 0, tmp;
	while (read < len) {
//		if (read + sizeof(tmp)
		tmp = ptrace(PTRACE_PEEKDATA, cpid, addr + read);
		if (errno != 0) {
			output("error reading from process: %m\n");
			free_mem(ret);
			return NULL;
		}
		memcpy(ret + read, &tmp, sizeof(tmp));
		read += sizeof(tmp);
	}
	return ret;
}
char *pid_fdpath(pid_t pid, int fd) {
	char *pid_fd_path = NULL, *link = NULL, *ret = NULL;

	if (fd == AT_FDCWD)
		return strdup("AT_FDCWD");

	asprintf(&pid_fd_path, "/proc/%d/fd/%d", pid, fd);
	link = malloc(PATH_MAX);
	readlinkat(AT_FDCWD, pid_fd_path, link, PATH_MAX);

	ret = strdup(link);
	free_mem(link);
	free_mem(pid_fd_path);

	return ret;
}
#define check_append(flags, flag, str, size) do { \
	if ((flags & flag) == flag) { \
		strncat(str, "|" #flag, size); \
		flags = flags & ~flag; \
	} \
} while (0)
#define MODE_STR_LEN 128
char *decode_open_mode(int flags) {
	char *mode = malloc(MODE_STR_LEN);

	if ((flags & 0x03) == O_RDONLY)
		strcpy(mode, "O_RDONLY");
	else if ((flags & 0x03) == O_WRONLY)
		strcpy(mode, "O_WRONLY");
	else if ((flags & 0x03) == O_RDWR)
		strcpy(mode, "O_RDWR");

	flags = flags & ~0x03;
	check_append(flags, O_CREAT, mode, MODE_STR_LEN - 1);
	check_append(flags, O_TRUNC, mode, MODE_STR_LEN - 1);
	check_append(flags, O_EXCL, mode, MODE_STR_LEN - 1);
	check_append(flags, O_NOCTTY, mode, MODE_STR_LEN - 1);
	check_append(flags, O_APPEND, mode, MODE_STR_LEN - 1);
	check_append(flags, O_NONBLOCK, mode, MODE_STR_LEN - 1);
	check_append(flags, O_NDELAY, mode, MODE_STR_LEN - 1);
	check_append(flags, O_SYNC, mode, MODE_STR_LEN - 1);
	check_append(flags, O_ASYNC, mode, MODE_STR_LEN - 1);
	check_append(flags, O_DIRECTORY, mode, MODE_STR_LEN - 1);
	check_append(flags, O_LARGEFILE, mode, MODE_STR_LEN - 1);
	check_append(flags, O_NOFOLLOW, mode, MODE_STR_LEN - 1);
	check_append(flags, O_DIRECT, mode, MODE_STR_LEN - 1);
	check_append(flags, O_CLOEXEC, mode, MODE_STR_LEN - 1);
	check_append(flags, O_PATH, mode, MODE_STR_LEN - 1);
	check_append(flags, O_NOATIME, mode, MODE_STR_LEN - 1);
	check_append(flags, O_DSYNC, mode, MODE_STR_LEN - 1);
	check_append(flags, O_TMPFILE, mode, MODE_STR_LEN - 1);

	if (flags)
		snprintf(mode + strlen(mode), MODE_STR_LEN - 1 - strlen(mode), "|0x%x", flags);

	return mode;
}

char *read_string(pid_t child, unsigned long addr) {
    char *val = malloc(4096);
    int allocated = 4096;
    int read = 0;
    unsigned long tmp;
    while (1) {
        if (read + sizeof tmp > allocated) {
            allocated *= 2;
            val = realloc(val, allocated);
        }
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
        if(errno != 0) {
            val[read] = 0;
            break;
        }
        memcpy(val + read, &tmp, sizeof tmp);
        if (memchr(&tmp, 0, sizeof tmp) != NULL)
            break;
        read += sizeof tmp;
    }
    return val;
}

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


#define try_replace_path(_cpid, _syscall, _regs, _reg) ({ \
	debug_output("%s (%llu) checking whether to replace '%s'\n", #_syscall, _regs.orig_rax, (char *)_regs._reg); \
output("%s reg %s expected to work, reg rdi: ", #_syscall, #_reg); \
try_output_str(rdi, _regs.rdi); \
output("%s reg %s expected to work, reg rsi: ", #_syscall, #_reg); \
try_output_str(rsi, _regs.rsi); \
	if (replace_this_path((char *)_regs._reg)) { \
		debug_output("%s('%s' -> '%s')\n", #_syscall, (char *)_regs._reg, (char *)(_regs._reg + 1)); \
		_regs._reg = _regs._reg + 1; \
		ptrace(PTRACE_SETREGS, _cpid, NULL, &_regs); \
	} \
})

#define debug_report_syscall(_syscall) do { \
	debug_output("syscall: %s (%d)\n", #_syscall, PASTE(SYS_, _syscall)); \
} while (0)

#define debug_report_syscall_case(_syscall) \
	case PASTE(SYS_, _syscall): \
		debug_report_syscall(_syscall); \
		catch_return(cpid); \
		break;

//		ptrace(PTRACE_SYSCALL, cpid, NULL, NULL); break; /* catch return */
//		debug_report_syscall(_syscall) ; break

#define quiet_syscall_case(_syscall) \
	case PASTE(SYS_, _syscall): \
		catch_return(cpid); \
		break;


#define PR(regs,r) output("%s: 0x%016llx\n", #r, regs.r)
void print_regs(struct user_regs_struct regs) {
	PR(regs, rax);
	PR(regs, rbx);
	PR(regs, rcx);
	PR(regs, rdx);
	PR(regs, rdi);
	PR(regs, rsi);
	PR(regs, r8);
	PR(regs, r9);
	PR(regs, r10);
	PR(regs, r11);
	PR(regs, r12);
	PR(regs, r13);
	PR(regs, r14);
	PR(regs, r15);

	PR(regs, ds);
	PR(regs, es);
	PR(regs, fs);
	PR(regs, ds);
	PR(regs, rbp);
	PR(regs, rip);
}

#define endian16(val) ( \
	(((val) >> 8) & 0xFF) | (((val) << 8) & 0xFF00) )
#define endian32(val) ( \
	(((val) >> 24) & 0x000000ff) | (((val) >>  8) & 0x0000ff00) | \
	(((val) <<  8) & 0x00ff0000) | (((val) << 24) & 0xff000000) )
#define endian64(val) ( \
	(((val) >> 56) & 0x00000000000000FFULL) | (((val) >> 40) & 0x000000000000FF00ULL) | \
	(((val) >> 24) & 0x0000000000FF0000ULL) | (((val) >>  8) & 0x00000000FF000000ULL) | \
	(((val) <<  8) & 0x000000FF00000000ULL) | (((val) << 24) & 0x0000FF0000000000ULL) | \
	(((val) << 40) & 0x00FF000000000000ULL) | (((val) << 56) & 0xFF00000000000000ULL) )

char inode_mode_type_char(uint32_t mode) {
	if (S_ISREG(mode))
		return '-';
	if (S_ISDIR(mode))
		return 'd';
	if (S_ISLNK(mode))
		return 'l';
	if (S_ISBLK(mode))
		return 'b';
	if (S_ISCHR(mode))
		return 'c';
	if (S_ISSOCK(mode))
		return 's';
	if (S_ISFIFO(mode))
		return 'p';
	return '?';
}

static const char *mbits[] = { "---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx" };
char *inode_mode_bits_string(uint32_t mode) {
	char ret[11] = { 0 }, *usr = ret + 1, *grp = ret + 4, *oth = ret + 7;
//	char *ret = malloc(11);
//	char *usr = ret + 1, *grp = ret + 4, *oth = ret + 7;
//	Yrwxrwxrwx
	int itype = mode & S_IFMT;
	int mode_bits = mode ^ itype;

	ret[0] = inode_mode_type_char(itype);

	strncpy(ret + 1, mbits[(mode_bits >> 6) & 7], 3);
	strncpy(ret + 4, mbits[(mode_bits >> 3) & 7], 3);
	strncpy(ret + 7, mbits[(mode_bits     ) & 7], 3);

	if (mode_bits & S_ISUID) {
		if (usr[2] == 'x')
			usr[2] = 's';
		else
			usr[2] = 'S';
	}
	if (mode_bits & S_ISGID) {
		if (grp[0] == 'x')
			grp[2] = 's';
		else
			grp[2] = 'S';
	}
	if (mode_bits & S_ISVTX) {
		if (oth[2] == 'x')
			oth[2] = 't';
		else
			oth[2] = 'T';
	}

	return strdup(ret);
}

bool decode_data(uint64_t offset, const char *data, uint64_t count) {
	uint64_t pos = 0;
	char magic[5] = { 0 };
	int blocks_found = 0;

	while (pos < count) {
//		uint64_t this_pos = (uint64_t)data + pos;
		uint64_t this_pos = offset + pos;

		/* might as well just do these calculations */
		uint64_t agno = POS_TO_AG(this_pos);
		uint64_t dblock = POS_TO_DBLOCK(this_pos);
		uint64_t fsblock = POS_TO_FSBLOCK(this_pos);
		uint64_t ag_block = POS_TO_AG_BLOCK(this_pos);
		uint64_t block_offset = POS_TO_AG_BLOCK_OFFSET(this_pos);

		memcpy(magic, data + pos, 4);

		if (isprint(magic[0])) {
			if (!isprint(magic[2]))
				magic[2] = '\0';
			else if (!isprint(magic[3]))
				magic[3] = '\0';

output("position %lu - disk block %lu, fsblock %lu, AG %lu, block in ag: %lu, offset in block: %lu - ",
	this_pos, dblock, fsblock, agno, ag_block, block_offset);

if (!strcmp("XFSB", magic)) {
	struct xfs_dsb *sb = (struct xfs_dsb *)(data + pos);

#define OSB(x) OSB8(x)
#define OSB8(str) do { \
	if (xfs_info.verbosity > 0) \
		output("    " #str " = %u\n", sb->PASTE(sb_, str)); \
} while (0)
#define OSB16(str) do { \
	if (xfs_info.verbosity > 0) \
		output("    " #str " = %u\n", endian16(sb->PASTE(sb_, str))); \
} while (0)
#define OSB32(str) do { \
	if (xfs_info.verbosity > 0) \
		output("    " #str " = %u\n", endian32(sb->PASTE(sb_, str))); \
} while (0)
#define OSB64(str) do { \
	if (xfs_info.verbosity > 0) \
		output("    " #str " = %llu\n", endian64(sb->PASTE(sb_, str))); \
} while (0)

	output("XFSB - super block %lu\n", agno);

	OSB32(blocksize);
	OSB64(dblocks);
	OSB64(rblocks);
	OSB64(rextents);
	if (xfs_info.verbosity > 0)
		output("    uuid\n");
	OSB64(logstart);
	OSB64(rootino);
	OSB64(rbmino);
	OSB64(rsumino);
	OSB32(rextsize);

	OSB32(agblocks);
	OSB32(agcount);
	OSB32(rbmblocks);
	OSB32(logblocks);
	OSB16(versionnum);
	OSB16(sectsize);
	OSB16(inodesize);
	OSB16(inopblock);

	if (xfs_info.verbosity > 0)
		output("    label: %s\n", sb->sb_fname);

	OSB(blocklog);
	OSB(sectlog);
	OSB(inodelog);
	OSB(inopblog);
	OSB(agblklog);
	OSB(rextslog);
	OSB(inprogress);
	OSB(imax_pct);
	OSB64(icount);
	OSB64(ifree);
	OSB64(fdblocks);
	OSB64(frextents);
	OSB64(uquotino);
	OSB64(gquotino);
	OSB16(qflags);
	OSB8(flags);
	OSB8(shared_vn);
	OSB32(inoalignmt);
	OSB32(unit);
	OSB32(width);
	OSB(dirblklog);
	OSB(logsectlog);
	OSB16(logsectsize);
	OSB32(logsunit);
	OSB32(features2);

	OSB32(bad_features2);

#undef OSB8
#undef OSB16
#undef OSB32
#undef OSB64




} else if (!strcmp("XAGF", magic)) { /* 2nd 512-byte block in each allocation group */
	struct xfs_agf *agf = (struct xfs_agf *)(data + pos);

	output("XAGF - (block allocation header) for AG %lu\n", agno);

	if (xfs_info.verbosity > 0) {
		output("    magic      = %u\n", endian32(agf->agf_magicnum));
		output("    magic      = %u\n", (agf->agf_magicnum));
		output("    versionnum = %u\n", endian32(agf->agf_versionnum));
		output("    seqno      = %u\n", endian32(agf->agf_seqno));
		output("    length     = %u\n", endian32(agf->agf_length));

		int i;
		for (i = 0 ; i < XFS_BTNUM_AGF ; i++)
			output("    agf_roots[%d]  = %u\n", i, endian32(agf->agf_roots[i]));
		for (i = 0 ; i < XFS_BTNUM_AGF ; i++)
			output("    agf_levels[%d] = %u\n", i, endian32(agf->agf_levels[i]));

		output("    flfirst    = %u\n", endian32(agf->agf_flfirst));
		output("    fllast     = %u\n", endian32(agf->agf_fllast));
		output("    flcount    = %u\n", endian32(agf->agf_flcount));
		output("    freeblks   = %u\n", endian32(agf->agf_freeblks));
		output("    longest    = %u\n", endian32(agf->agf_longest));
		output("    btreeblks  = %u\n", endian32(agf->agf_btreeblks));
		output("    uuid\n");
		output("    rmap_blocks = %u\n", endian32(agf->agf_rmap_blocks));
		output("    refcount_blocks   = %u\n", endian32(agf->agf_refcount_blocks));
		output("    refcount_root     = %u\n", endian32(agf->agf_refcount_root));
		output("    refcount_level    = %u\n", endian32(agf->agf_refcount_level));
		output("    lsn               = %llx\n", endian64(agf->agf_lsn));
		output("    crc        = %u\n", endian32(agf->agf_crc));
	}
} else if (!strcmp("XAGI", magic)) { /* 3rd 512-byte block in each allocation group */
	output("XAGI (inode allocation block) for AG %lu\n", agno);
} else if (!strcmp("AGFL", magic)) { /* 3rd 512-byte block in each allocation group */
	output("AGFL (block numbers which can be used) for AG %lu\n", agno);
} else if (!strncmp("IN", magic, 2)) {
	char *mode_str = NULL;
//	xfs_dinode_t *dinode = (xfs_dinode_t*)(data + pos);
	struct xfs_dinode *dinode = (struct xfs_dinode*)(data + pos);
	uint64_t inum = POS_TO_INODE_NUM(this_pos);
	uint64_t *pinode = (uint64_t *)(data + pos + 0x98);



/*
core.magic = 0x494e
core.mode = 0
core.version = 3
core.format = 0 (dev)
core.nlinkv2 = 0
core.onlink = 0
core.projid_lo = 0
core.projid_hi = 0
core.uid = 0
core.gid = 0
core.flushiter = 0
core.atime.sec = Wed Dec 31 18:00:00 1969
core.atime.nsec = 0
core.mtime.sec = Wed Dec 31 18:00:00 1969
core.mtime.nsec = 0
core.ctime.sec = Wed Dec 31 18:00:00 1969
core.ctime.nsec = 0
core.size = 0
core.nblocks = 0
*/
	magic[2] = '\0';


	if (dinode->di_mode) {

//	if (dinode->

		mode_str = inode_mode_bits_string(endian16(dinode->di_mode));
		output("IN - inode %lu - %s (0%04o0 - 0x%08x) \n", inum, mode_str, endian16(dinode->di_mode), endian16(dinode->di_mode));


	} else {
		output("IN - inode %lu - unallocated inode\n", inum);
	}

	if (endian64(*pinode) != endian64(dinode->di_ino)) {
		output("uhmm... mismatch between pinode %llu and di_ino %llu\n", endian64(*pinode), endian64(dinode->di_ino));
	}

	if (inum < endian64(*pinode))
		output("actual inode number is greater than estimated by %llu\n", endian64(*pinode) - inum);
	else if (inum > endian64(*pinode))
		output("estimated inode number is greater than actual by %llu\n", endian64(*pinode) - inum);


	free_mem(mode_str);

//	hexdump("    ", data + pos, min(count, 512));
} else {
	output("type: %s\n", magic);
//	output("position %lu - disk block %lu, AG %lu, block in ag: %lu, offset in block: %lu - type: %s\n",
//		this_pos, fsblock, ag, ag_block, block_offset, magic);
}
//output("%s%s", blocks_found++ ? " " : "", magic);
blocks_found++;

//	output("pread64(%d) of %llu bytes at filesystem location AG %lu block %lu offset %lu (%lu)\n",
//		(int)SYSCALL_ARG_0(regs), SYSCALL_ARG_2(regs), POS_TO_AG(offset), POS_TO_AG_BLOCK(offset), POS_TO_AG_BLOCK_OFFSET(offset), offset);

		}
		pos += 512;
	}
//	if (blocks_found)
//		output("\n");
	return blocks_found != 0;
}

int wait_for_syscall(pid_t cpid) {
	int status;

	while (42) {
		ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
		waitpid(cpid, &status, 0);
		if (WIFSTOPPED(status)) {
			if (WSTOPSIG(status) == SIGTRAP) // why sometimes with 0x80 and sometimes without?
				return 0;
			if (WSTOPSIG(status) == (SIGTRAP | 0x80))
				return 0;
			if (WSTOPSIG(status) == SIGSTOP)
				return 0;
			output("stop signal: %d\n", WSTOPSIG(status));
		}
		if (WIFEXITED(status)) {
			xfs_info.child_exited = true;
			return 1;
		} else if (WIFSIGNALED(status)) {
			output("xfs_repair exited with signal\n");
			xfs_info.child_exited = true;
			return 1;
		}
	}
}

int trace_xfs_repair_pid(pid_t cpid) {
	struct user_regs_struct regs;

	ptrace(PTRACE_ATTACH, cpid, NULL, NULL);
	ptrace(PTRACE_SETOPTIONS, cpid, 0, PTRACE_O_EXITKILL);
	ptrace(PTRACE_SETOPTIONS, cpid, 0, PTRACE_O_TRACESYSGOOD);
	ptrace(PTRACE_SETOPTIONS, cpid, 0, PTRACE_O_TRACEEXEC);



//	ptrace(PTRACE_CONT, cpid, 0, 0);


	int status;
	waitpid(cpid, &status, 0); // we'll get a notification of the child's exec()
//	waitpid(cpid, &status, 0); // we'll get a notification of the child's exec()
//	waitpid(cpid, &status, 0); // we'll get a notification of the child's exec()



//	ptrace(PTRACE_SETOPTIONS, cpid, 0, PTRACE_O_TRACECLONE);

	/*
       PTRACE_SETOPTIONS (since Linux 2.4.6; see BUGS for caveats)
              Set ptrace options from data.  (addr is ignored.)  data is interpreted as a bit mask of options, which are specified by the following flags:

              PTRACE_O_EXITKILL (since Linux 3.8)
                     Send a SIGKILL signal to the tracee if the tracer exits.  This option is useful for ptrace jailers that want to ensure that tracees can never escape the tracer's control.

              PTRACE_O_TRACECLONE (since Linux 2.5.46)
*/

//	kill(cpid, SIGCONT);
//	ptrace(PTRACE_CONT, cpid, 0, 0);

	while (1) {
		if (xfs_info.child_exited)
			break;
/*
		waitpid(cpid, &status, 0);
		if (WIFEXITED(status))
			break;
		else if (WIFSIGNALED(status)) {
			output("xfs_repair exited with signal\n");
			xfs_info.child_exited = true;
			continue;
		}
*/
		if (wait_for_syscall(cpid))
			continue;

		if (ptrace(PTRACE_GETREGS, cpid, NULL, &regs) == -1) {
			debug_output("error calling ptrace(GETREGS) %d: %m\n", errno);
			ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
			continue;
		}

//		output("checking syscall regs.orig_rax: %llu\n", regs.orig_rax);
/*
output("%s ... rdi: %llu, rsi: 0x%016llx, rdx: 0x%016llx\n", "?", SYSCALL_ARG_0(regs), SYSCALL_ARG_1(regs), SYSCALL_ARG_2(regs));
if ((SYSCALL_ARG_0(regs) & 0x00007ff000000000) == 0x00007ff000000000) {
	printf("rdi looks printable: %s\n", (char *)SYSCALL_ARG_0(regs));
}
if ((SYSCALL_ARG_1(regs) & 0x00007ff000000000) == 0x00007ff000000000) {
	printf("rsi looks printable: %s\n", (char *)SYSCALL_ARG_1(regs));
}
*/
		switch (SYSCALL_NUM(regs)) {
			case SYS_open: {
				char *filename = read_string(cpid, SYSCALL_ARG_1(regs));
				int open_mode = (int)SYSCALL_ARG_1(regs);
				char *open_mode_str = decode_open_mode(open_mode);

				if (open_mode & O_CREAT)
					output("open(\"%s\", %s, %llo)", filename, open_mode_str, SYSCALL_ARG_2(regs));
				else
					output("open(\"%s\", %s)", filename, open_mode_str);

//				output("%s - %%rdi: 0x%016llx, %%rsi: 0x%016llx, %%rdx: 0x%016llx\n",
//					"open", SYSCALL_ARG_0(regs), SYSCALL_ARG_1(regs), SYSCALL_ARG_2(regs));
//				try_output_str(rsi, SYSCALL_ARG_0(regs));

//				char *filename = read_string(cpid, SYSCALL_ARG_0(regs));
//				output("%s - %%rdi: 0x%016llx (%s), %%rsi: 0x%016llx, %%rdx: 0x%016llx\n",
//					"open", SYSCALL_ARG_0(regs), filename, SYSCALL_ARG_1(regs), SYSCALL_ARG_2(regs));

				catch_return(cpid);
				if (xfs_info.child_exited)
					continue;
				ptrace(PTRACE_GETREGS, cpid, NULL, &regs);

				if ((int)SYSCALL_REG_RET(regs) >= 0)
					output(" = %d\n", (int)SYSCALL_REG_RET(regs));
				else // error ?
					output(" = %d - ???\n", (int)SYSCALL_REG_RET(regs));

				free_mem(open_mode_str);
				free_mem(filename);
			}; break;
//       long syscall(SYS_openat2, int dirfd, const char *pathname,
//                    struct open_how *how, size_t size);
			case SYS_openat: {
				char *filename = read_string(cpid, SYSCALL_ARG_1(regs));
				char *pid_fd_str = pid_fdpath(cpid, (int)SYSCALL_ARG_0(regs));
				int open_mode = (int)SYSCALL_ARG_2(regs);
				char *open_mode_str = decode_open_mode(open_mode);

				if (open_mode & O_CREAT) {
					output("openat(%d<%s>, \"%s\", %s, %llo)", (int)SYSCALL_ARG_0(regs), pid_fd_str, filename, open_mode_str, SYSCALL_ARG_3(regs));
				} else
					output("openat(%d<%s>, \"%s\", %s)", (int)SYSCALL_ARG_0(regs), pid_fd_str, filename, open_mode_str);

//				if (filename && strlen(filename)) {
//					output("    string: %s\n", filename);
//				}

				catch_return(cpid);
				ptrace(PTRACE_GETREGS, cpid, NULL, &regs);
/*
				if ((int)SYSCALL_REG_RET(regs) == -38) {
					int foo;
					output("why did this return -38?");
					foo = ptrace(PTRACE_PEEKUSER, cpid, sizeof(long) * RAX);

					print_regs(regs);

					output("now it's %d\n", foo);
				}
*/

				if ((int)SYSCALL_REG_RET(regs) >= 0)
					output(" = %d\n", (int)SYSCALL_REG_RET(regs));
				else
					output(" = %d - ???\n", (int)SYSCALL_REG_RET(regs));

				if (!strcmp(filename, xfs_info.devpath)) {
					xfs_info.fs_fd = SYSCALL_REG_RET(regs);
					output("this is the fd of the filesystem device/image: %d\n", xfs_info.fs_fd);
				}
				free_mem(open_mode_str);
				free_mem(pid_fd_str);
				free_mem(filename);

			} ; break;
			case SYS_lseek:
				if (SYSCALL_ARG_0(regs) == xfs_info.fs_fd) {
					output("lseek on filesystem to position %llu from %s\n",
						SYSCALL_ARG_1(regs),
							SYSCALL_ARG_2(regs) == SEEK_SET ? "SEEK_SET" :
							SYSCALL_ARG_2(regs) == SEEK_CUR ? "SEEK_CUR" :
							SYSCALL_ARG_2(regs) == SEEK_END ? "SEEK_END" :
							"UNKNOWN");
				}
				catch_return(cpid);
				ptrace(PTRACE_GETREGS, cpid, NULL, &regs);
				if (SYSCALL_ARG_0(regs) == xfs_info.fs_fd) {
					xfs_info.fs_fd_pos = SYSCALL_REG_RET(regs);

					output("lseek on filesystem to position %lu - filesystem location AG %lu block %lu offset %lu\n",
//						POS_TO_AG(SYSCALL_REG_RET(regs)), POS_TO_AG_BLOCK(SYSCALL_REG_RET(regs)), POS_TO_AG_BLOCK_OFFSET(SYSCALL_REG_RET(regs)), SYSCALL_REG_RET(regs));
						xfs_info.fs_fd_pos, POS_TO_AG(xfs_info.fs_fd_pos), POS_TO_AG_BLOCK(xfs_info.fs_fd_pos), POS_TO_AG_BLOCK_OFFSET(xfs_info.fs_fd_pos));
				}

				break;
			case SYS_pread64: // ssize_t pread(int fd, void *buf, size_t count, off_t offset);a
				{
					int fd = SYSCALL_ARG_0(regs);
					uint64_t buf_addr = SYSCALL_ARG_1(regs);
					uint64_t count = SYSCALL_ARG_2(regs);
					uint64_t offset = SYSCALL_ARG_3(regs);

					if (SYSCALL_ARG_0(regs) == xfs_info.fs_fd) {
						output("pread64(%d) of %lu bytes at filesystem location AG %lu block %lu offset %lu (%lu)\n",
							fd, count, POS_TO_AG(offset), POS_TO_AG_BLOCK(offset), POS_TO_AG_BLOCK_OFFSET(offset), offset);

						if (offset > xfs_info.fs_size) {
							output("OOPS!  offset is too large\n");
						} else if (offset + count > xfs_info.fs_size) {
							output("OOPS!  offset + count is larger than the filesystem size\n");
						}

if (offset <= 1099511787520 && 1099511787520 <= (offset + count)) {
	output("***** THIS pread64 should include inode 2147483968 *****\n");
}

					}
					catch_return(cpid);
					if (fd == xfs_info.fs_fd) {
						uint64_t count;
						char *data = NULL;

						ptrace(PTRACE_GETREGS, cpid, NULL, &regs);
						count = SYSCALL_REG_RET(regs); // bytes read

						output("pread64 returned %lu\n", count);
						data = read_bytes(cpid, buf_addr, count);
						if (data) {
//							hexdump("    ", data, count);
							decode_data(offset, data, count);
							free_mem(data);
						}
					}
				} break;
			case SYS_read: { // ssize_t read(int fd, void *buf, size_t count);
				int fd = SYSCALL_ARG_0(regs);
				uint64_t buf_addr = SYSCALL_ARG_1(regs);
				uint64_t count = SYSCALL_ARG_2(regs);

				if (fd == xfs_info.fs_fd) {
					output("read(fd %d) of %lu bytes at location AG %lu block %lu offset %lu (%lu)\n",
						(int)fd, count, POS_TO_AG(xfs_info.fs_fd_pos), POS_TO_AG_BLOCK(xfs_info.fs_fd_pos), POS_TO_AG_BLOCK_OFFSET(xfs_info.fs_fd_pos), xfs_info.fs_fd_pos);



					if (xfs_info.fs_fd_pos <= 1099511787520 && 1099511787520 <= (xfs_info.fs_fd_pos + count)) {
						output("***** THIS pread64 should include inode 2147483968 *****\n");
					}
				}
				catch_return(cpid);
				if (fd == xfs_info.fs_fd) {
					uint64_t count_read;
					char *data = NULL;

					ptrace(PTRACE_GETREGS, cpid, NULL, &regs);
					count_read = SYSCALL_REG_RET(regs); // bytes read

					output("read returned %lu\n", count_read);
					if (count != count_read)
						output("number of bytes read (%lu) is not equal to bytes requested (%lu)\n", count_read, count);
					data = read_bytes(cpid, buf_addr, count_read);
					if (data) {
//							hexdump("    ", data, count);
						decode_data(xfs_info.fs_fd_pos, data, count_read);

						free_mem(data);
					}
					xfs_info.fs_fd_pos += count_read;
				}
			}; break;
			case SYS_write: {
				int fd = SYSCALL_ARG_0(regs);
//				uint64_t buf_addr = SYSCALL_ARG_1(regs);

				output("write(fd %d)\n", fd);
				if (fd == xfs_info.fs_fd) {
					output("writing %llu bytes to the filesystem at position %lu - AG %lu block %lu offset %lu\n",
						SYSCALL_ARG_2(regs), xfs_info.fs_fd_pos, POS_TO_AG(xfs_info.fs_fd_pos), POS_TO_AG_BLOCK(xfs_info.fs_fd_pos), POS_TO_AG_BLOCK_OFFSET(xfs_info.fs_fd_pos));
				}
//				debug_report_syscall(write); break;
				catch_return(cpid);
				if (fd == xfs_info.fs_fd) {
					uint64_t count = SYSCALL_REG_RET(regs);

					xfs_info.fs_fd_pos += count;
				}



//				debug_report_syscall(write); break;
//				debug_report_syscall(write); break;
				} break;
			case SYS_close:
				if (SYSCALL_ARG_0(regs) == xfs_info.fs_fd) {
					output("closing filesystem\n");
					xfs_info.fs_fd = -1;
				} else
					output("close %d\n", (int)SYSCALL_ARG_0(regs));


				catch_return(cpid);

				break;
//			debug_report_syscall_case(close);
			quiet_syscall_case(mmap);
			quiet_syscall_case(munmap);
			quiet_syscall_case(mprotect);
			quiet_syscall_case(fstat);

			case SYS_ioctl: {
// ioctl(fd 3, 0x800c581e - XFS_IOC_DIOINFO
// ioctl(fd 3, 0x8100587e - XFS_IOC_FSGEOMETRY

/* ioctls likely to be called
BLKBSZGET
BLKBSZSET
BLKDISCARD
BLKFLSBUF
BLKGETSIZE
BLKGETSIZE64
BLKIOMIN
BLKIOOPT
BLKROTATIONAL
BLKSSZGET
FITRIM
FS_IOC_ADD_ENCRYPTION_KEY
FS_IOC_FIEMAP
FS_IOC_FSGETXATTR
FS_IOC_FSSETXATTR
FS_IOC_GET_ENCRYPTION_KEY_STATUS
FS_IOC_GET_ENCRYPTION_POLICY_EX
FS_IOC_GETFSLABEL
FS_IOC_GETFSMAP
FS_IOC_SET_ENCRYPTION_POLICY
FS_IOC_SETFSLABEL
HDIO_GETGEO
SG_IO
XFS_IOC_AG_GEOMETRY
XFS_IOC_ALLOCSP
XFS_IOC_ALLOCSP64
XFS_IOC_ATTR_
XFS_IOC_ATTR_CREATE
XFS_IOC_ATTRCTL_BY_HANDLE
XFS_IOC_ATTR_LIST_BY_HANDLE
XFS_IOC_ATTRLIST_BY_HANDLE
XFS_IOC_ATTR_MULTI_BY_HANDLE
XFS_IOC_ATTRMULTI_BY_HANDLE
XFS_IOC_ATTR_REPLACE
XFS_IOC_ATTR_ROOT
XFS_IOC_ATTR_SECURE
XFS_IOC_BULKSTAT
XFS_IOC_CLONE
XFS_IOC_CLONE_RANGE
XFS_IOC_DIOINFO - 0x800c581e
XFS_IOC_ERROR_CLEARALL
XFS_IOC_ERROR_INJECTION
XFS_IOC_FD_TO_HANDLE
XFS_IOC_FILE_EXTENT_SAME
XFS_IOC_FREE_EOFBLOCKS
XFS_IOC_FREESP
XFS_IOC_FREESP64
XFS_IOC_FREEZE
XFS_IOC_FS
XFS_IOC_FSBULKSTAT
XFS_IOC_FSBULKSTAT_SINGLE
XFS_IOC_FSCOUNTERS
XFS_IOC_FSCOUNTS
XFS_IOC_FSGEOMETRY - 0x8100587e
XFS_IOC_FSGEOMETRY_V1
XFS_IOC_FSGEOMETRY_V4
XFS_IOC_FSGETXATTR
XFS_IOC_FSGETXATTRA
XFS_IOC_FSGROWFSDATA
XFS_IOC_FSGROWFSLOG
XFS_IOC_FSGROWFSRT
XFS_IOC_FSINUMBERS
XFS_IOC_FSSETDM
XFS_IOC_FSSETDM_BY_HANDLE
XFS_IOC_FSSETXATTR
XFS_IOC_GETBIOSIZE
XFS_IOC_GETBMAP
XFS_IOC_GETBMAPA
XFS_IOC_GETBMAPX
XFS_IOC_GETFSMAP
XFS_IOC_GETFSUUID
XFS_IOC_GET_RESBLKS
XFS_IOC_GETVERSION
XFS_IOC_GETXATTR
XFS_IOC_GETXFLAGS
XFS_IOC_GOINGDOWN
XFS_IOC_INUMBERS
XFS_IOC_OPEN_BY_HANDLE
XFS_IOC_PATH_TO_FSHANDLE
XFS_IOC_PATH_TO_HANDLE
XFS_IOC_READLINK_BY_HANDLE
XFS_IOC_RESVSP
XFS_IOC_RESVSP64
XFS_IOC_SCRUB_METADATA
XFS_IOC_SETBIOSIZE
XFS_IOC_SET_RESBLKS
XFS_IOC_SETXFLAGS
XFS_IOC_SWAPEXT
XFS_IOC_THAW
XFS_IOC_UNRESVSP
XFS_IOC_UNRESVSP64
XFS_IOC_ZERO_RANGE
*/
				output("ioctl(fd %d, 0x%llx\n", (int)SYSCALL_ARG_0(regs), SYSCALL_ARG_1(regs));
				catch_return(cpid);
			} ; break;
//			debug_report_syscall_case(ioctl);


			quiet_syscall_case(set_robust_list);
			debug_report_syscall_case(clone);

			debug_report_syscall_case(execve);
			quiet_syscall_case(mincore);
			debug_report_syscall_case(set_tid_address);
			debug_report_syscall_case(request_key);
			quiet_syscall_case(madvise);

//debug_report_syscall_case(clone3);
			case SYS_clone3: {
				//output("clone3?\n");
				//kill(cpid, SIGABRT);
				catch_return(cpid);
			}; break;
			quiet_syscall_case(fcntl);


			case -1:
catch_return(cpid);
break;
			default:
if (0) {
				debug_output("unrecognized syscall: %llu; regs - "
					"rdi: %llu, rsi: 0x%016llx, rdx: 0x%016llx, rcx: 0x%016llx\n",
					regs.orig_rax, SYSCALL_ARG_0(regs), SYSCALL_ARG_1(regs), SYSCALL_ARG_2(regs), SYSCALL_ARG_3(regs));
}
catch_return(cpid);
				break;
		}
//		ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
	}
	output("parent detected the child exited\n");
	return EXIT_SUCCESS;
//	exit(EXIT_SUCCESS);
}

int launcher(void) {
        char *argv[] = { "/usr/sbin/xfs_repair", "-fv", xfs_info.devpath, NULL };
        char *newenv[] = { NULL };

	output("child process stopping for parent signal\n");
	ptrace(PTRACE_TRACEME);
	raise(SIGSTOP);
	output("child process starting repair\n");

	execve(argv[0], argv, newenv);
	exit(EXIT_FAILURE);
}

#if 0
           struct clone_args {
               u64 flags;        /* Flags bit mask */
               u64 pidfd;        /* Where to store PID file descriptor
                                    (int *) */
               u64 child_tid;    /* Where to store child TID,
                                    in child's memory (pid_t *) */
               u64 parent_tid;   /* Where to store child TID,
                                    in parent's memory (pid_t *) */
               u64 exit_signal;  /* Signal to deliver to parent on
                                    child termination */
               u64 stack;        /* Pointer to lowest byte of stack */
               u64 stack_size;   /* Size of stack */
               u64 tls;          /* Location of new TLS */
               u64 set_tid;      /* Pointer to a pid_t array
                                    (since Linux 5.5) */
               u64 set_tid_size; /* Number of elements in set_tid
                                    (since Linux 5.5) */
               u64 cgroup;       /* File descriptor for target cgroup
                                    of child (since Linux 5.7) */
           };
#endif

long clone3(struct clone_args *args) {
	return syscall(__NR_clone3, args, sizeof(struct clone_args));
}

pid_t start_xfs_repair(void) {
	pid_t cpid;
//	char *stack = calloc(1, STACK_SIZE);
	struct clone_args args = {
		.flags = 0,
		.pidfd = (uint64_t)&xfs_info.pidfd,
		.child_tid = (uint64_t)&xfs_info.child_tid,
		.parent_tid = (uint64_t)&xfs_info.parent_tid,
		.exit_signal = SIGCHLD,
//		.stack = (uint64_t)stack + STACK_SIZE,
//		.stack_size = STACK_SIZE,
		.tls = 0,
	};

	if ((cpid = clone3(&args)) == 0) { /* child */
		int ret = launcher();
		exit(ret);
	} else if (cpid < 0) {
		output("error cloning child process: %m\n");
		exit(EXIT_FAILURE);
	}
	output("tracing child pid %d\n", cpid);
	return trace_xfs_repair_pid(cpid);
}

int main(int argc, char *argv[]) {

	xfs_info.fs_size = xfs_info.agsize * xfs_info.agcount * xfs_info.block_size;
	output("filesystem size in bytes: %lu\n", xfs_info.fs_size);

	if (argc == 2) {
		pid_t xfs_repair_pid = strtol(argv[1], NULL, 10);
		if (xfs_repair_pid) {
			xfs_info.child_tid = xfs_repair_pid;
			output("tracing existing xfs_repair pid %d\n", xfs_info.child_tid);
			return trace_xfs_repair_pid(xfs_info.child_tid);
		}
	} else
		start_xfs_repair();


	return EXIT_FAILURE;
}
