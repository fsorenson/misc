#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

main()
{
        int fd, i, j;
        struct stat t_stat;
        struct statfs t_statfs;
        char tmp[1024];
        pid_t mypid=getpid();
        struct timespec tim;

        tim.tv_sec = 0;
        tim.tv_nsec = 500000L;

        for (i=0; i<10; i++) {
                close(i);
                sprintf(tmp, "/var/tmp/shane/file%i.%i", mypid, i);
                fd=open(tmp, O_CREAT|O_RDWR, 0644);
                if (fd==-1) fd=open(tmp, O_RDWR);
        }
        while (1) {
                for (i=0; i<10; i++) {
                        close(i);
                        sprintf(tmp, "/var/tmp/shane/file%i.%i", mypid, i);
                        stat(tmp, &t_stat);
                        statfs(tmp, &t_statfs);
                        access(tmp, F_OK);
                        fd=open(tmp, O_RDWR);
                        stat(tmp, &t_stat);
                        statfs(tmp, &t_statfs);
                }
        }
}
