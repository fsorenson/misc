/*
	utility to migrate one or two processes back & forth
	between two numa nodes

	Frank Sorenson <sorenson@redhat.com>, 2015

	# gcc swish.c -o swish -lnuma
*/

#include <stdio.h>
#include <numa.h>

int main(int argc, char *argv[]) {
	struct bitmask *node0, *node1;
	char *err_string = "%s: numa error occurred while '%s': %m";
	char *err_action = "";
	int pid1 = 0;
	int pid2 = 0;
	int ret;

	if (argc < 2) {
		printf("Usage: %s <pid1> [<pid2>]\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	pid1 = strtol(argv[1], NULL, 10);
	if (argc == 3)
		pid2 = strtol(argv[2], NULL, 10);

	if (numa_available() == -1) {
		printf("NUMA is not available\n");
		exit(EXIT_FAILURE);
	}

	node0 = numa_allocate_nodemask();
	node1 = numa_allocate_nodemask();

	numa_bitmask_setbit(node0, 0);
	numa_bitmask_setbit(node1, 1);
	while (1) {
		if ((ret = numa_migrate_pages(pid1, node1, node0)) != 0) {
			err_action = "migrate_pages pid1: node1->node0";
			break;
		}
		if (pid2) {
			if ((ret = numa_migrate_pages(pid2, node0, node1)) != 0) {
				err_action = "migrate_pages pid2: node0->node1";
				break;
			}
		}

		if ((ret = numa_migrate_pages(pid1, node0, node1)) != 0) {
			err_action = "migrate_pages pid1: node0->node1";
			break;
		}
		if (pid2) {
			if ((ret = numa_migrate_pages(pid2, node1, node0)) != 0) {
				err_action = "migrate_pages pid2: node1->node0";
				break;
			}
		}
	}
	numa_warn(ret, err_string, argv[0], err_action);

	numa_free_nodemask(node0);
	numa_free_nodemask(node1);

	return EXIT_SUCCESS;
}
