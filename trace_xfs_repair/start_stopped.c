#define _GNU_SOURCE

#include <stdlib.h>
#include <sys/wait.h>

#include "common.h"

int launcher(int argc, char *argv[]) {
//        char *argv[100] = { NULL };
        char *newenv[] = { NULL };
	int i;

for (i = 0 ; i < argc ; i++) {
	output("arg %d: %s\n", i, argv[i]);
}


	raise(SIGSTOP);
	execve(argv[0], argv, newenv);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
	int cpid;

	if ((cpid = fork()) == 0) {
		launcher(argc - 1, &argv[1]);
		return EXIT_FAILURE;
	} else if (cpid > 0) {
		output("started '%s' as child pid %d\n", argv[1], cpid);
	} else {
		output("error forking: %m\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
