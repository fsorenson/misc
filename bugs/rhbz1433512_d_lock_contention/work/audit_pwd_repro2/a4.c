#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define NUM_FILES 10

int main(int argc, char *argv[]) {
	char **filenames;
        struct stat t_stat;
        pid_t mypid = getpid();
	char *cwd;
	char *f;
        int i;

	cwd = get_current_dir_name();
	filenames = malloc(NUM_FILES * sizeof(char *));
	for (i=0 ; i < NUM_FILES ; i++)
		asprintf(&filenames[i], "%s/file%i.%i", cwd, mypid, i);
	free(cwd);

	close(fileno(stdin));
	close(fileno(stdout));
	close(fileno(stderr));
	while (1) {
		for (i = 0 ; i < NUM_FILES ; i++) {
			f = filenames[i];
			stat(f, &t_stat);
			access(f, F_OK);
			stat(f, &t_stat);
		}
	}
}
