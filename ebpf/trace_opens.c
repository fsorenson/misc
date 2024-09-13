#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bcc/libbpf.h>
#include <bpf/libbpf.h>
#include <signal.h>

//int bpf_attach_tracepoint(int progfd, const char *tp_category,
//                          const char *tp_name);
//int bpf_detach_tracepoint(const char *tp_category, const char *tp_name);

#define NSEC 1000000000ULL
#define PINDIR "/sys/fs/bpf/trace_opens"
#define OBJ_FILE "trace_opens.bpf.o"

struct timespec boot_time_offset = {0, 0};
struct global_data_struct {
	uint64_t offset_sec;
	uint64_t offset_nsec;
} global_data = { 0, 0};


#define ATTACH_SYSCALL_TP0(i, name) do { \
	snprintf(tp, sizeof(tp) - 1, PINDIR "/tracepoint_syscalls_sys_%s", name); \
	if ((fds[i] = openat(dfd, tp, O_RDWR)) < 0) { \
		printf("error opening pinned path '%s': %m\n", tp); \
		return EXIT_FAILURE; \
	} \
	if ((bpf_attach_tracepoint(fds[i], "syscalls", name)) < 0) { \
		printf("bpf_attach_tracepoint returned %m\n"); \
		return EXIT_FAILURE; \
	} \
} while (0)
#define ATTACH_SYSCALL_TP(i, name) do { \
	snprintf(tp, sizeof(tp) - 1, PINDIR "/tracepoint_syscalls_sys_%s", name); \
	if ((fds[i] = bpf_obj_get(tp)) < 0) { \
		printf("error opening object '%s': %m\n", tp); \
		return EXIT_FAILURE; \
	} \
} while (0)

int interrupted = false;
void handle_interrupt(int signum) {
	interrupted = true;
}

int bpf_obj__count_progs(struct bpf_object *bpf_obj) {
        struct bpf_program *program_pos;
	int count = 0;

        bpf_object__for_each_program(program_pos, bpf_obj)
		count++;
	return count;
}

uint64_t ts_nsec(const struct timespec ts) {
	return (ts.tv_sec * NSEC) + ts.tv_nsec;
}

struct timespec ts_diff(const struct timespec ts1, const struct timespec ts2) {
        struct timespec diff, a, b;

	if ((ts1.tv_sec > ts2.tv_sec) ||
		((ts1.tv_sec == ts2.tv_sec) && (ts1.tv_nsec >= ts2.tv_nsec))) {
		a = ts1; b = ts2;
	} else
		{ a = ts2; b = ts1; }
	diff.tv_sec = a.tv_sec - b.tv_sec - 1;
	diff.tv_nsec = a.tv_nsec - b.tv_nsec + NSEC;
	while (diff.tv_nsec >= NSEC) {
		diff.tv_sec++;
		diff.tv_nsec -= NSEC;
	}
	return diff;
}



#define TIME_ESTIMATE_ITER 5
void estimate_boottime(void) {
	struct timespec ts[TIME_ESTIMATE_ITER][3];
	struct timespec ts3_ts1[TIME_ESTIMATE_ITER];
	uint64_t delta_ns[TIME_ESTIMATE_ITER];
	int min_i = 0, i;

	for (i = 0 ; i < TIME_ESTIMATE_ITER ; i++) {
		clock_gettime(CLOCK_REALTIME, &ts[i][0]);
		clock_gettime(CLOCK_BOOTTIME, &ts[i][1]);
		clock_gettime(CLOCK_REALTIME, &ts[i][2]);
		ts3_ts1[i] = ts_diff(ts[i][2], ts[i][0]);
		delta_ns[i] = ts_nsec(ts3_ts1[i]);
		if (delta_ns[i] < delta_ns[min_i])
			min_i = i;
	}
	uint64_t min_avg = delta_ns[min_i] / 2;
	struct timespec best_boottime = ts[min_i][1];
	best_boottime.tv_sec += min_avg / NSEC;
	best_boottime.tv_nsec += min_avg % NSEC;
	while (best_boottime.tv_nsec >= NSEC) {
		best_boottime.tv_sec++;
		best_boottime.tv_nsec -= NSEC;
	}
	boot_time_offset = ts_diff(ts[min_i][2], best_boottime);
	printf("offset %ld.%09ld\n", boot_time_offset.tv_sec, boot_time_offset.tv_nsec);
	global_data.offset_sec = boot_time_offset.tv_sec;
	global_data.offset_nsec = boot_time_offset.tv_nsec;
}

int main(int argc, char *argv[]) {
	struct sigaction sa;
	int prog_count = 0;
	char tp[512];
	int dfd, fds[4];


	struct bpf_object *bpf_obj;
	struct bpf_program **prog;
	struct bpf_map *global_data_map;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &handle_interrupt;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	estimate_boottime();

	if ((bpf_obj = bpf_object__open_file(OBJ_FILE, NULL)) == NULL) {
		printf("error opening bpf object file: %m\n");
		return EXIT_FAILURE;
	}
	if (bpf_object__load(bpf_obj)) {
		printf("failed to load: %m\n");
		return EXIT_FAILURE;
	}
	if (interrupted)
		goto out_unload;

	if ((bpf_object__pin_programs(bpf_obj, PINDIR)) < 0) {
		printf("error pinning: %m\n");
		return EXIT_FAILURE;
	}
	if (interrupted)
		goto out_unpin;


	global_data_map = bpf_object__find_map_by_name(bpf_obj, "global_data");
	printf("got global data map: %p\n", global_data_map);

	int global_data_map_fd = bpf_map__fd(global_data_map);
	uint32_t key_zero = 0;
	if ((bpf_update_elem(global_data_map_fd, &key_zero, &global_data, BPF_ANY)) < 0) {
		printf("error with bpf_update_elem: %m\n");
	}


	prog_count = bpf_obj__count_progs(bpf_obj);
	prog = malloc(sizeof(struct bpf_program*) * prog_count);

	struct bpf_program *program_pos;
	int i = 0;
	bpf_object__for_each_program(program_pos, bpf_obj) {
		const char *prog_name = bpf_program__name(program_pos);
		const char *section_name = bpf_program__section_name(program_pos);
		printf("attaching object program: %s (size: %lu) from section %s\n",
			prog_name, bpf_program__size(program_pos), section_name);
		prog[i] = program_pos;
		bpf_program__attach(prog[i++]);

		if (interrupted)
			break;
	}

	while (!interrupted)
		sleep(1);

out_unpin:
	bpf_object__unpin_programs(bpf_obj, PINDIR);
out_unload:
	bpf_object__unload(bpf_obj);

	return EXIT_SUCCESS;
}
