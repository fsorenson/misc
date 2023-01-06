/*
	Frank Sorenson - <sorenson@redhat.com>, 2023

	allocate_larger_than_size.c - create a file with an allocation larger than the filesize

	$ gcc -Wall allocate_larger_than_size.c -o allocate_larger_than_size && ./allocate_larger_than_size
	SUCCESS - allocated larger than file size
	    file size: 1072849907, allocated size: 1914830848
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

#define TESTFILE "testfile"
#define REAL_FILESIZE (1072849907)
#define APPARENT_FILESIZE  (1869952 * 1024)

int main(int argc, char *argv[]) {
	char buf[1048576];
	struct stat st;
	int fd;

	memset(buf, 0, sizeof(buf));

	unlink(TESTFILE);
	if ((fd = open(TESTFILE, O_RDWR|O_CREAT|O_TRUNC, 0644)) < 0) {
		printf("error opening testfile: %m\n");
		return EXIT_FAILURE;
	}

	/* preallocate, but keep filesize */
	/* see manpage for fallocate:
		If the FALLOC_FL_KEEP_SIZE flag is specified in mode,
		the behavior of the call is similar, but the file
		size will not be changed even if offset+len is greater
		than the file size.  Preallocating zeroed blocks
		beyond the end of the file in this manner is useful
		for optimizing append workloads.
	*/
	fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, APPARENT_FILESIZE);
	fallocate(fd, 0, 0, REAL_FILESIZE); /* allocate the file */

	close(fd);
	stat(TESTFILE, &st);


	printf("%s larger than file size\n",
		(st.st_blocks * 512 > st.st_size) ? "SUCCESS - allocated" : "FAILURE - unable to allocate");

	printf("    file size: %lu, allocated size: %lu\n",
		st.st_size, st.st_blocks * 512);
	return (st.st_blocks * 512 > st.st_size) ? EXIT_SUCCESS : EXIT_FAILURE;
}
