// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Frank Sorenson <sorenson@redhat.com>
#include "vmlinux.h"
#include <stdio.h>
#include <stdarg.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define NSEC 1000000000ULL

// 64-bit *boottime* nsec
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} open_entries SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// boottime -> epoch offset
struct global_data_struct {
	uint64_t offset_sec;
	uint64_t offset_nsec;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct global_data_struct);
} global_data SEC(".maps");


struct syscalls_enter_open_args {
	unsigned long long unused;
	long syscall_nr;
	long filename_ptr;
	long flags;
	long mode;
};
struct syscalls_exit_open_args {
	unsigned long long unused;
	long syscall_nr;
	long ret;
};

u64 get_current_time() {
	u64 ts = bpf_ktime_get_ns();
	struct global_data_struct *gd;
	int zero = 0;

	gd = bpf_map_lookup_elem(&global_data, &zero);
	if (gd)
		ts += (gd->offset_sec * NSEC) + gd->offset_nsec;

	return ts;
}

int strcmp(const char *a, const char *b) {
	while (*a && *a == *b) {
		++a; ++b;
	}
	return (int)(unsigned char)(*a) - (int)(unsigned char)(*b);
}

static __always_inline int trace_enter(unsigned long path_ptr) {
	char comm[32] = {};

	if (!bpf_get_current_comm(&comm, sizeof(comm))) {
		if (!strcmp(comm, "dspmq")) {
			char filename[256] = {};
			u64 now = get_current_time();
			int pid = bpf_get_current_pid_tgid() >> 32;

			bpf_core_read_user_str(filename, sizeof(filename), path_ptr);

			bpf_printk("%d.%09ld: ", now / NSEC, now % NSEC);
			bpf_printk("Hello world! from '%s' pid %d open()ing '%s'",
				comm, pid, filename);
			bpf_map_update_elem(&open_entries, &pid, &now, BPF_ANY);
		}
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx) {
	return trace_enter(ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx) {
	return trace_enter(ctx->args[1]);
}

static __always_inline int trace_exit(struct trace_event_raw_sys_exit* ctx) {
	int pid = bpf_get_current_pid_tgid() >> 32;
	u64 *value;

	value = bpf_map_lookup_elem(&open_entries, &pid);
	if (value) {
		u64 now = get_current_time();
		u64 diff = now - *value;
		bpf_printk("open returning after %d.%09ld seconds",
			diff / NSEC, diff % NSEC);
	}

	bpf_map_delete_elem(&open_entries, &pid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit *ctx) {
	return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
	return trace_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";
