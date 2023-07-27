/*
	Frank Sorenson <sorenson@redhat.com>, 2023


	Display xattrs attached to a file/directory,
	and decode as many of them as possible
*/

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <attr/xattr.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <acl/libacl.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <linux/fs.h>
#include <sys/vfs.h>
*/

#include "capability.h"
#include <asm/byteorder.h>


static uint32_t sansflags(uint32_t m) {
	return m & ~VFS_CAP_FLAGS_EFFECTIVE;
}

bool is_v2header(size_t size, const struct vfs_cap_data *cap) {
	if (size != XATTR_CAPS_SZ_2)
		return false;
	return sansflags(__le32_to_cpu(cap->magic_etc)) == VFS_CAP_REVISION_2;
}
bool is_v3header(size_t size, const struct vfs_cap_data *cap) {
	if (size != XATTR_CAPS_SZ_3)
		return false;
	return sansflags(__le32_to_cpu(cap->magic_etc)) == VFS_CAP_REVISION_3;
}
static bool validheader(size_t size, const void *ptr) {
	const struct vfs_cap_data *cap = (const struct vfs_cap_data *)ptr;
	return is_v2header(size, cap) || is_v3header(size, cap);
}
uid_t get_rootid(size_t size, const void *ptr) {
	uid_t rootid = 0;

	if (size == XATTR_CAPS_SZ_3)
		rootid = __le32_to_cpu(((const struct vfs_ns_cap_data *)ptr)->rootid);
	return rootid;
}

#define V(n) { .val = n, .str = #n }

const struct val_str_pair CAP_NAMES[] = {
	V(CAP_CHOWN),
	V(CAP_DAC_OVERRIDE),
	V(CAP_DAC_READ_SEARCH),
	V(CAP_FOWNER),
	V(CAP_FSETID),
	V(CAP_KILL),
	V(CAP_SETGID),
	V(CAP_SETUID),
	V(CAP_SETPCAP),
	V(CAP_LINUX_IMMUTABLE),
	V(CAP_NET_BIND_SERVICE),
	V(CAP_NET_BROADCAST),
	V(CAP_NET_ADMIN),
	V(CAP_NET_RAW),
	V(CAP_IPC_LOCK),
	V(CAP_IPC_OWNER),
	V(CAP_SYS_MODULE),
	V(CAP_SYS_RAWIO),
	V(CAP_SYS_CHROOT),
	V(CAP_SYS_PTRACE),
	V(CAP_SYS_PACCT),
	V(CAP_SYS_ADMIN),
	V(CAP_SYS_BOOT),
	V(CAP_SYS_NICE),
	V(CAP_SYS_RESOURCE),
	V(CAP_SYS_TIME),
	V(CAP_SYS_TTY_CONFIG),
	V(CAP_MKNOD),
	V(CAP_LEASE),
	V(CAP_AUDIT_WRITE),
	V(CAP_AUDIT_CONTROL),
	V(CAP_SETFCAP),
	V(CAP_MAC_OVERRIDE),
	V(CAP_MAC_ADMIN),
	V(CAP_SYSLOG),
	V(CAP_WAKE_ALARM),
	V(CAP_BLOCK_SUSPEND),
	V(CAP_AUDIT_READ),
	V(CAP_PERFMON),
	V(CAP_BPF),
	V(CAP_CHECKPOINT_RESTORE),
};


#define _KERNEL_CAPABILITY_U32S    _LINUX_CAPABILITY_U32S_3

typedef struct kernel_cap_struct {
	uint32_t cap[_KERNEL_CAPABILITY_U32S];
} kernel_cap_t;


struct cpu_vfs_cap_data {
        __u32 magic_etc;
        kernel_cap_t permitted;
        kernel_cap_t inheritable;
        uint32_t rootid;
};


#define CAP_FOR_EACH_U32(__capi)  \
	for (__capi = 0; __capi < _KERNEL_CAPABILITY_U32S; ++__capi)

void *show_capability(const char *attr_name, const unsigned char *buf, int len, bool is_dir) {
	unsigned char *p = (unsigned char *)buf;
	const struct vfs_cap_data *caps = buf;
	struct cpu_vfs_cap_data cpu_caps = { 0 };
	uint32_t magic_etc, rootid = 0;
	unsigned i;
	int tocopy;


	if (len < sizeof(magic_etc))
		goto ESIZE;
	magic_etc = __le32_to_cpu(caps->magic_etc);
	switch (magic_etc & VFS_CAP_REVISION_MASK) {
		case VFS_CAP_REVISION_1:
			if (len != XATTR_CAPS_SZ_1)
				goto ESIZE;
			tocopy = VFS_CAP_U32_1;
			break;
		case VFS_CAP_REVISION_2:
			if (len != XATTR_CAPS_SZ_2)
				goto ESIZE;
			tocopy = VFS_CAP_U32_2;
			break;
		case VFS_CAP_REVISION_3:
			if (len != XATTR_CAPS_SZ_3)
				goto ESIZE;
			tocopy = VFS_CAP_U32_3;
			rootid = get_rootid(len, buf);
			break;
		default:
			output("Invalid version: %u\n",
				magic_etc & VFS_CAP_REVISION_MASK);
			goto out;
			break;
	}

	output("\trootid: %d\n", rootid);

	CAP_FOR_EACH_U32(i) {
		uint32_t permitted = 0, inheritable = 0;
		if (i >= tocopy)
			break;
		permitted = __le32_to_cpu(caps->data[i].permitted);
		inheritable = __le32_to_cpu(caps->data[i].inheritable);
		output("%d - permitted: %x\n", i, permitted);
		output("%d - inheritable: %x\n", i, inheritable);
	}

/*

	if (!validheader(len, buf)) {
		printf("invalid header\n");
		return NULL;
	}
	printf("\tvalid header\n");

	printf("\trootid: %d\n", get_rootid(len, buf));
*/

out:
	return NULL;

ESIZE:
	output("Bad size\n");
	goto out;
}
