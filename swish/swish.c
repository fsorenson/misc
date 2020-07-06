/*
	utility to migrate one or two processes back & forth
	between two numa nodes

	Frank Sorenson <sorenson@redhat.com>, 2015

	# gcc swish.c -o swish -lnuma
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <numa.h>

int usage(char *cmd, int ret) {
	printf("Usage: %s <pid1> [<pid2>] [<pid3>] ...\n", cmd);

	return ret;
}

int main(int argc, char *argv[]) {
	struct bitmask **numa_nodes = NULL;
	char *err_string = "%s: numa error occurred while '%s': %m";
	char *err_action = NULL;
	int numa_node_count = -1;
	int pid_count, valid_pids = 0;
	pid_t *pids = NULL;
	int node_rot = 0;
	int ret;
	int i;

	if (numa_available() == -1) {
		printf("NUMA is not available\n");
		return usage(argv[0], EXIT_FAILURE);
	}

	if (argc < 2)
		return usage(argv[0], EXIT_FAILURE);

	pid_count = argc - 1;
	pids = malloc(sizeof(pid_t) * pid_count);
	for (i = 1 ; i < argc ; i++) {
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

//	printf("size of bitmask: %ld\n", sizeof(struct bitmask));
	numa_node_count = numa_num_configured_nodes();
	numa_nodes = malloc(sizeof(struct bitmask *) * numa_node_count);
	for (i = 0 ; i < numa_node_count ; i++) {
		numa_nodes[i] = numa_allocate_nodemask();
		numa_bitmask_clearall(numa_nodes[i]);
//		numa_nodes[i] = numa_bitmask_alloc(numa_node_count);
		numa_bitmask_setbit(numa_nodes[i], i);
	}
	printf("configured numa nodes: %d\n", numa_node_count);
	printf("swishing %d pid%s\n", valid_pids, valid_pids > 1 ? "s" : "");

	while (42) {
		for (i = 0 ; i < valid_pids ; i++) {
			int cur_node = (i + node_rot) % numa_node_count;
			int next_node = (i + node_rot + 1) % numa_node_count;

//			printf("swish %d from node%d->node%d\n", pids[i], cur_node, next_node);

retry_migrate:
			if ((ret = numa_migrate_pages(pids[i], numa_nodes[cur_node], numa_nodes[next_node])) != 0) {
				if (ret > 0)
					goto retry_migrate;
				asprintf(&err_action, "migrate_pages pid %d from node%d->node%d",
					pids[i], cur_node, next_node);
				goto out_err;
			}
		}
		node_rot = (node_rot + 1) % numa_node_count;
	}

out_err:
	numa_warn(ret, err_string, argv[0], err_action);

	for (i = 0 ; i < numa_node_count ; i++) {
		numa_free_nodemask(numa_nodes[i]);
	}
	free(numa_nodes);
	free(pids);

	return EXIT_SUCCESS;
}
