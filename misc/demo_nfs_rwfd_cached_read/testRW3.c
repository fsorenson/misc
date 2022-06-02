#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define BUF_SIZE 4096
#define READ_DELAY 10000 /* usec */
#define WRITE_DELAY 199999 /* usec */
#define NOP_DELAY 500000 /* usec */

#define USE_STREAMS 0

#if USE_STREAMS
#else
#endif

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

int usage(const char *exe, int ret) {
	output("testRW usage:\n");
	output("\t%s <open_mode> <action> <filename>\n", exe);
	output("\t<open_mode>\n");
	output("\t\t0 - read-only\n");
	output("\t\t1 - write-only, write at end\n");
	output("\t\t2 - write-only, truncating\n");
	output("\t\t3 - read-write, write at end\n");
	output("\t\t4 - read-write, truncating\n");
	output("\t<action>\n");
	output("\t\t0 - read\n");
	output("\t\t1 - write\n");
	output("\t\t2 - no IO\n");
	return ret;
}

int set_lock(int fd, short int lock_type) {
	struct flock fl = {
		.l_type = lock_type,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
	};

retry:
	if ((fcntl(fd, F_SETLKW, &fl)) < 0) {
		if (errno == EINTR)
			goto retry; /* interrupted by signal */
		return -1;
	}
	return 0;
}

int main (int argc, char **argv) {
	if (argc != 4)
		return usage(argv[0], -1);

	int arg1 = atoi(argv[1]);
	int arg2 = atoi(argv[2]);
	int fd, open_flags = 0;
#if USE_STREAMS
	char *open_mode = "";
	FILE *file;
#endif
	char *filename = argv[3];

	switch (arg1) {
		case 0:
			open_flags = O_RDONLY;
#if USE_STREAMS
			open_mode = "r";
#endif
			break;
		case 2:
			open_flags = O_TRUNC;
		case 1:
			open_flags |= O_WRONLY|O_CREAT;
#if USE_STREAMS
			open_mode = "r+"; // actually no equivalent to O_WRONLY
#endif
			break;

		case 4:
			open_flags = O_TRUNC;
		case 3:
			open_flags |= O_RDWR|O_CREAT;
#if USE_STREAMS
			open_mode = "r+";
#endif
			break;
		default:
			output("Error selecting open mode; %s is out-of-range\n", argv[1]);
			return usage(argv[0], -1);
	}
	if (arg2 == 0 && (open_flags & (O_RDONLY|O_WRONLY|O_RDWR)) == O_WRONLY) {
		output("cannot read from file opened write-only\n");
		return -1;
	}
	if (arg2 == 1 && (open_flags & (O_RDONLY|O_WRONLY|O_RDWR)) == O_RDONLY) {
		output("cannot write to file opened read-only\n");
		return -1;
	}

	if (!(open_flags & O_CREAT))
		fd = open(filename, open_flags);
	else
		fd = open(filename, open_flags, 0666);

	if (fd < 0) {
		output("error opening filename '%s': %m\n", filename);
		return -1;
	}


	if ((open_flags & (O_RDONLY|O_WRONLY|O_RDWR)) != O_RDONLY) // values: 0, 1, 2
		lseek(fd, 0, SEEK_END); // move position to end of file


	if (arg2 == 0) { // Read
#if USE_STREAMS
		file = fdopen(fd, open_mode);
		setlinebuf(file); // set line buffering

		fd = fileno(file);
#endif
		char *buf = malloc(BUF_SIZE);
		uint64_t last_fpos = 0xffffffffffffffff;
		while (42) {
			ssize_t nread;
			uint64_t fpos;
#if USE_STREAMS
			size_t len = 0;

			fpos = ftell(file); // *** stream *** position
			if (fpos != last_fpos)
				printf("stream position: %ld, file position: %ld\n\t", fpos, lseek(fd, 0, SEEK_CUR));
#else

			fpos = lseek(fd, 0, SEEK_CUR); // *** position of fd ***
			if ((fpos = lseek(fd, 0, SEEK_CUR)) != last_fpos)
				output("file position: %ld\n\t", fpos);
#endif
			last_fpos = fpos;

#if USE_STREAMS
			if (feof(file))
				clearerr(file);
#endif
			if (set_lock(fd, F_RDLCK))
				output("Error locking file: %m\n");
#if USE_STREAMS
			nread = getline(&buf, &len, file);
#else
			nread = read(fd, buf, BUF_SIZE);
			buf[BUF_SIZE - 1] = '\0';
			if (nread) { // seek back to fake line buffering (the 'right' way)
				int i;
				for (i = 0 ; i < nread ; i++) {
					if (buf[i] == '\n') {
						i++;
						nread = i;
						break;
					}
				}
				fpos = lseek(fd, last_fpos + nread + 1, SEEK_SET);
			}
#endif
			set_lock(fd, F_UNLCK);
			if (nread > 0) {
				buf[nread] = '\0';
				output("%s", buf);
			}

			usleep(READ_DELAY);
		}
	} else if (arg2 == 1) { // Write
#if USE_STREAMS
		file = fdopen(fd, open_mode);
		setlinebuf(file); // set line buffering
#endif
		for (int i = 0; i < 100000; i++) {
			const char buf[] = "012345678901234567890123456789\n";
			long fpos;
			if (set_lock(fd, F_WRLCK))
				output("Error locking file: %m\n");

#if USE_STREAMS
			fwrite(buf, 1, sizeof(buf), file);
			fpos = ftell(file); // *** stream *** position
#else
			write(fd, buf, sizeof(buf));
			fpos = lseek(fd, 0, SEEK_CUR); // *** file *** position
#endif
			output("pos: %ld\r", fpos);
			set_lock(fd, F_UNLCK);
			usleep(WRITE_DELAY);
		}
	} else {
		for (int i = 0; i < 100000; i++) {
			output(".\n");
			usleep(NOP_DELAY);
		}
	}
	close(fd);

	return 0;
}
