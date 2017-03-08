#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>


void do_copy_stuff(char *s_file, char *d_file) {
	char buf[BUFSIZ];
	int s_fd;
	int d_fd;
	int ret;
	struct stat st;

	stat(d_file, &st);
	d_fd = open(d_file, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	s_fd = open(s_file, O_RDONLY);
//	sched_yield();
//	sync();
//	sched_yield();
	ret = read(s_fd, buf, BUFSIZ);
//	sync();
//	sched_yield();
	write(d_fd, buf, ret);
	close(d_fd);
	close(s_fd);
}

int main(int argc, char *argv[]) {

	unlink("/etc/init/control-alt-delete.override");
	sched_yield();
	do_copy_stuff("/tmp/control-alt-delete.conf-orig", "/etc/init/control-alt-delete.conf");
	sync();
	sleep(1);
	sched_yield();


	do_copy_stuff("/tmp/control-alt-delete.override", "/etc/init/control-alt-delete.override");
//	sched_yield();
	truncate("/etc/init/control-alt-delete.conf", 0);
	do_copy_stuff("/tmp/control-alt-delete.conf", "/etc/init/control-alt-delete.conf");

	return 0;
}
