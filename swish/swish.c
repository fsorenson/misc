/*
	utility to migrate one or two processes back & forth
	between two numa nodes

	Frank Sorenson <sorenson@redhat.com>, 2015, 2020

	# gcc swish.c -o swish -lnuma
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <numa.h>
#include <getopt.h>
#include <errno.h>

int usage(char *cmd, int ret) {
	printf("Usage: %s [ -m ] [ -c ] [ -o <offset> ] <pid1> [<pid2>] [<pid3>] ...\n", cmd);
	printf("\t-m - swish process memory between numa nodes\n");
	printf("\t-c - swich process execution between numa nodes\n");
	printf("\t-c <offset> - swish memory and execution to different numa nodes,\n");
	printf("\t\toffset by <offset> nodes (implies both memory and execution)\n");
	printf("\n");
	printf("\tif neither memory nor execution are swished, the default will be\n");
	printf("\t\tto swish only memory between nodes\n");

	return ret;
}

#define print_bitmask(_b) do { \
	int _s = sizeof(*_b); \
	int _i; \
	unsigned char *_p = (unsigned char *)(_b->maskp); \
	printf("bitmask %p (%d bytes): ", _b, _s); \
	printf("  size: %lu, mask: ", _b->size); \
	for (_i = 0 ; _i < _s ; _i++) { \
		printf("%02x", _p[(_s - _i - 1)]); \
	} \
	printf("\n"); \
} while (0)

static struct option long_opts[] = {
	{ "mem", no_argument, NULL, 'm' },
	{ "cpu", no_argument, NULL, 'c' },
	{ "offset", required_argument, NULL, 'o' },
	{ NULL, 0, 0, 0 },
};

int main(int argc, char *argv[]) {
	struct bitmask **numa_mem_nodes = NULL;
	struct bitmask **numa_cpu_nodes = NULL;
	char *err_string = "%s: numa error occurred while '%s': %m";
	int node_rot = 0, mem_cpu_offset = 0;
	bool swish_mem = false, swish_cpus = false;
	int pid_count, valid_pids = 0;
	int numa_node_count = -1;
	char *err_action = NULL;
	pid_t *pids = NULL;
	int ret, i, arg;

	if (numa_available() == -1) {
		printf("NUMA is not available\n");
		return usage(argv[0], EXIT_FAILURE);
	}

	while ((arg = getopt_long(argc, argv, "mco:", long_opts, NULL)) != EOF) {
		switch (arg) {
			case 'm':
				swish_mem = true;
				break;
			case 'c':
				swish_cpus = true;
				break;
			case 'o':
				mem_cpu_offset = strtol(optarg, NULL, 10);
				if (mem_cpu_offset < 0)
					mem_cpu_offset = 0;
				else
					swish_mem = swish_cpus = true;
				break;
			default:
				return usage(argv[0], EXIT_FAILURE);
				break;
		}
	}
	if (swish_mem == false && swish_cpus == false)
		swish_mem = true;

	pid_count = argc - optind;
	pids = malloc(sizeof(pid_t) * pid_count);
	for (i = optind ; i < argc ; i++) {
		pid_t tmp_pid = (pid_t)strtoul(argv[i], NULL, 10);
		if (tmp_pid < 1) {
			printf("invalid pid: %d\n", tmp_pid);
			continue;
		}
		if (kill(tmp_pid, 0) < 0) {
			printf("pid %d requested, but not running\n", tmp_pid);
			continue;
		}
		pids[valid_pids++] = tmp_pid;
	}
	if (valid_pids < 1) {
		printf("no valid pids found\n");
		return usage(argv[0], EXIT_FAILURE);
	}

	numa_node_count = numa_num_configured_nodes();
	printf("configured numa nodes: %d\n", numa_node_count);
	if (numa_node_count < 2) {
		printf("not enough numa nodes to swish\n");
		return usage(argv[0], EXIT_FAILURE);
	}

	mem_cpu_offset = mem_cpu_offset % numa_node_count;

	if (swish_mem)
		numa_mem_nodes = malloc(sizeof(struct bitmask *) * numa_node_count);
	if (swish_cpus)
		numa_cpu_nodes = malloc(sizeof(struct bitmask *) * numa_node_count);
	for (i = 0 ; i < numa_node_count ; i++) {
		if (swish_mem) {
			numa_mem_nodes[i] = numa_allocate_nodemask();
			numa_bitmask_clearall(numa_mem_nodes[i]);
			numa_bitmask_setbit(numa_mem_nodes[i], i);

//			printf("node bitmask %d:\n    ", i);
//			print_bitmask(numa_mem_nodes[i]);
		}
		if (swish_cpus) {
			numa_cpu_nodes[i] = numa_allocate_cpumask();
			numa_node_to_cpus(i, numa_cpu_nodes[i]);

//			printf("node cpu bitmask %d:\n    ", i);
//			print_bitmask(numa_cpu_nodes[i]);
		}
	}
	printf("swishing %d pid%s\n", valid_pids, valid_pids > 1 ? "s" : "");
	printf("swishing %s%s%s",
		swish_mem ? "memory" : "",
		swish_mem && swish_cpus ? ", " : "",
		swish_cpus ? "cpus" : "");
	if (swish_mem && swish_cpus && mem_cpu_offset > 0)
		printf(" (memory & cpu nodes offset by %d node%s)",
			mem_cpu_offset,
			mem_cpu_offset > 1 ? "s" : "");
	printf(" of %d pid%s",
		valid_pids,
		valid_pids > 1 ? "s" : "");
	printf(" between %d node%s\n",
		numa_node_count,
		numa_node_count > 1 ? "s" : "");

	while (42) {
		for (i = 0 ; i < valid_pids ; i++) {
			int cur_node, next_node;

			if (swish_mem) {
				cur_node = (i + node_rot) % numa_node_count;
				next_node = (i + node_rot + 1) % numa_node_count;
retry_migrate:
				if ((ret = numa_migrate_pages(pids[i], numa_mem_nodes[cur_node], numa_mem_nodes[next_node])) != 0) {
					if (ret > 0)
						goto retry_migrate;
					asprintf(&err_action, "migrate_pages pid %d from node%d->node%d",
						pids[i], cur_node, next_node);
					goto out_err;
				}
			}
			if (swish_cpus) {
				next_node = (i + node_rot + mem_cpu_offset) % numa_node_count;

retry_setaffinity:
				if ((ret = numa_sched_setaffinity(pids[i], numa_cpu_nodes[next_node])) < 0) {
					printf("numa_sched_setaffinity() returned %d: %m\n", ret);
					if (errno == ESRCH)
						goto out_err;
					goto retry_setaffinity;
				}
			}
		}
		node_rot = (node_rot + 1) % numa_node_count;
	}

out_err:
	numa_warn(ret, err_string, argv[0], err_action);

	for (i = 0 ; i < numa_node_count ; i++) {
		if (swish_mem)
			numa_free_nodemask(numa_mem_nodes[i]);
		if (swish_cpus)
			numa_free_cpumask(numa_cpu_nodes[i]);
	}
	if (swish_mem)
		free(numa_mem_nodes);
	if (swish_cpus)
		free(numa_cpu_nodes);
	free(pids);

	return EXIT_SUCCESS;
}
