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

#define NSEC 1000000000ULL
#define PINDIR "/sys/fs/bpf/trace_opens"
#define OBJ_FILE "trace_opens.bpf.o"
#define BOOTTIME_ESTIMATE_ITER 5

struct global_data_struct {
	uint64_t offset_sec;
	uint64_t offset_nsec;
} global_data = { 0, 0};

int interrupted = false;
void handle_interrupt(int signum) {
	interrupted = true;
}

int bpf_obj__count_progs(struct bpf_object *bpf_obj) {
        struct bpf_program *pos;
	int count = 0;

        bpf_object__for_each_program(pos, bpf_obj)
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

void estimate_boottime(void) {
	struct timespec ts[BOOTTIME_ESTIMATE_ITER][3];
	uint64_t delta_ns[BOOTTIME_ESTIMATE_ITER], boot_delta;
	int min_i = 0, i;

	for (i = 0 ; i < BOOTTIME_ESTIMATE_ITER ; i++) {
		clock_gettime(CLOCK_REALTIME, &ts[i][0]);
		clock_gettime(CLOCK_BOOTTIME, &ts[i][1]);
		clock_gettime(CLOCK_REALTIME, &ts[i][2]);
		delta_ns[i] = ts_nsec(ts[i][2]) - ts_nsec(ts[i][0]);

		if (delta_ns[i] < delta_ns[min_i])
			min_i = i;
	}
	boot_delta = ts_nsec(ts[min_i][0]) + delta_ns[min_i] / 2 - ts_nsec(ts[min_i][1]);
	global_data.offset_sec = boot_delta / NSEC;
	global_data.offset_nsec = boot_delta % NSEC;

	printf("boottime offset %ld.%09ld\n", global_data.offset_sec, global_data.offset_nsec);
}

int main(int argc, char *argv[]) {
	struct bpf_program **prog, *prog_pos;
	int i = 0, prog_count = 0, zero = 0;
	struct bpf_map *global_data_map;
	struct bpf_object *bpf_obj;
	int global_data_map_fd;
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &handle_interrupt;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

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

	estimate_boottime();
	global_data_map = bpf_object__find_map_by_name(bpf_obj, "global_data");
	global_data_map_fd = bpf_map__fd(global_data_map);

	if ((bpf_update_elem(global_data_map_fd, &zero, &global_data, BPF_ANY)) < 0)
		printf("error with bpf_update_elem: %m\n");

	prog_count = bpf_obj__count_progs(bpf_obj);
	prog = malloc(sizeof(struct bpf_program*) * prog_count);

	bpf_object__for_each_program(prog_pos, bpf_obj) {
		const char *prog_name = bpf_program__name(prog_pos);
		const char *section_name = bpf_program__section_name(prog_pos);
		printf("attaching object program: %s (size: %lu) from section %s\n",
			prog_name, bpf_program__size(prog_pos), section_name);
		prog[i] = prog_pos;
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
