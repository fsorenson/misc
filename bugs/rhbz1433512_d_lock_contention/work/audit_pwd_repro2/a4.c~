#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define KiB (1024ULL)
#define MiB (KiB * KiB)

//#define REPRO_DIR "/root/audit_pwd_repro2"
#define REPRO_DIR "./"
#define NUM_FILES 10
#define BUF_SIZE (1ULL * MiB)

int main(int argc, char *argv[]) {
        struct stat t_stat;
        struct statfs t_statfs;
	char **filenames;
	int *fds;
        pid_t mypid=getpid();
        int fd, i, j;
	char *f;
	char *buf;
	char *cwd;

	cwd = get_current_dir_name();
	filenames = malloc(NUM_FILES * sizeof(char *));
	fds = malloc(NUM_FILES * sizeof(int));

	close(fileno(stdin));
	close(fileno(stdout));
	close(fileno(stderr));
	buf = malloc(BUF_SIZE);
	memset(buf, 0xAA, BUF_SIZE);
	for (i=0 ; i < NUM_FILES ; i++) {
//                close(i);
		asprintf(&filenames[i], "%s/file%i.%i", cwd, mypid, i);
//		fds[i] = open(filenames[i], O_CREAT|O_TRUNC|O_RDWR, 0644);
//		fd = open(filenames[i], O_CREAT|O_TRUNC|O_RDWR, 0644);
//		write(fd, buf, BUF_SIZE);
//		close(fds[i]);
	}
	free(cwd);
	while (1) {
		for (i = 0 ; i < NUM_FILES ; i++) {
			f = filenames[i];

//			fd = open(f, O_RDWR);
#if 0
			for (j = 0 ; j < 100 ; j++) {
				fstat(fd, &t_stat);
				fstatfs(fd, &t_statfs);
				fstat(fd, &t_stat);
				fstatfs(fd, &t_statfs);

			}
#endif
#if 0
				pread(fd, buf, BUF_SIZE, 0);
#endif

#if 1

			stat(f, &t_stat);
//			statfs(f, &t_statfs);
			access(f, F_OK);
#if 1
//			close(fd);
#endif
			stat(f, &t_stat);
//			statfs(f, &t_statfs);
#endif
#if 0
			close(fd);
#endif
		}
	}
}
