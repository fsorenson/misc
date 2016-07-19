/*
	Frank Sorenson <sorenson@redhat.com>
	Red Hat, 2016
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>


#define THREADS  3
#define COUNTER_WRAP 100000

pthread_t tid[THREADS];
static char *test_file;

void *work(void *arg) {
	unsigned long i = 0;
	char buf[BUFSIZ];
	int fd;
	int len;

	while (1) {
		len = snprintf(buf, BUFSIZ, "count: %lu\n", i++);

		fd = open(test_file, O_RDWR | O_CREAT | O_APPEND, 0660);
		write(fd, buf, len);
		close(fd);
		if (i > COUNTER_WRAP)
			i = 0;
	}
	return NULL;
}

int main(int argc, char *argv[]) {
	int i;
	int ret;

	if (argc != 2) {
		printf("Usage: %s <test_file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	test_file = argv[1];

	for (i = 0 ; i < THREADS ; i++) {
		ret = pthread_create(&(tid[i]), NULL, &work, NULL);
		if (ret != 0)
			printf("\nthread creation failed: %m\n");
		else
			printf("\nthread %d created\n", i);
	}

	for (i = 0 ; i < THREADS ; i++)
		pthread_join(tid[i], NULL);
	sleep(2);
	return 0;
}
