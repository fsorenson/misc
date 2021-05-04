/*
	Frank Sorenson <sorenson@redhat.com>, 2021

	program to demonstrate how a zombie process is created
*/
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	if (fork() != 0) { /* parent process */
		while (42)
			sleep(1);
	}
	/* child process drops through and exits immediately */

	return 0;
}
