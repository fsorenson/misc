#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
	printf("my uid is %ld\n", getuid());
	printf("my euid is %ld\n", geteuid());

	printf("my gid is %ld\n", getgid());
	printf("my egid is %ld\n", getegid());

	printf("my fsuid is %ld\n", setfsuid(-1));
	printf("my fsgid is %ld\n", setfsgid(-1));

	return EXIT_SUCCESS;
}

