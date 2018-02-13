#include <unistd.h>

int main(int argc, char *argv[]) {
//        execve(argv[0], NULL, NULL);
	while (1) {
		execve("./NOFILE", NULL, NULL);
	}
}
