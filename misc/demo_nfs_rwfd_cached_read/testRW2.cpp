#include <iostream>
#include <fstream>
#include <unistd.h>
#include <stdlib.h>
#include <bitset>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ext/stdio_filebuf.h>

using namespace std;

int usage(const char *exe, int ret) {
	cout << "testRW usage:\n"
	<< exe << " <open_mode> <action> <filename>\n"
	<< "\t<open_mode>\n"
	<< "\t\t0 - read-only\n"
	<< "\t\t1 - write-only\n"
	<< "\t\t2 - write-only, truncating\n"
	<< "\t\t3 - read-write\n"
	<< "\t\t4 - read-write, truncating\n"
	<< "\t<action>\n"
	<< "\t\t0 - read\n"
	<< "\t\t1 - write\n"
	<< "\t\t2 - no IO\n"
//	<< "./testRW 2 0 filename  # Open file in RW mode, read from file\n"
//	<< "./testRW 2 1 filename  # Open file in RW mode, write to file\n"
//	<< "./testRW 2 2 filename  # Open file in RW mode" << endl;
	<< endl;
	return ret;
}

int set_lock(int fd, short int lock_type) {
	struct flock64 fl = {
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
	std::ios_base::openmode open_mode;
	int fd,  open_flags = 0;
	char *filename = argv[3];

	switch (arg1) {
		case 0:
			open_flags = O_RDONLY;
			open_mode = fstream::in;
			break;
		case 2:
			open_flags = O_TRUNC;
		case 1:
			open_flags |= O_WRONLY|O_CREAT;
			open_mode = fstream::out;
			break;

		case 4:
			open_flags = O_TRUNC;
		case 3:
			open_flags |= O_RDWR|O_CREAT;
			open_mode = fstream::out;
			break;
		default:
			cout << "Error selecting open mode\n"
			<< arg1 << "is out-of-range\n";
			return usage(argv[0], -1);
	}
	if (arg2 == 0 && (open_flags & (O_RDONLY|O_WRONLY|O_RDWR)) == O_WRONLY) {
		cout << "cannot read from file opened write-only" << endl;
		return -1;
	}
	if (arg2 == 1 && (open_flags & (O_RDONLY|O_WRONLY|O_RDWR)) == O_RDONLY) {
		cout << "cannot write to file opened read-only" << endl;
		return -1;
	}

	if ((open_flags & (O_RDONLY|O_WRONLY|O_RDWR)) == O_RDONLY) // values: 0, 1, 2
		fd = open(filename, open_flags);
	else
		fd = open(filename, open_flags, 0666);

	if (fd < 0) {
		cout << "error opening filename '" << filename << "': "
			<< strerror(errno) << endl;
		return -1;
	}
	if ((open_flags & (O_RDONLY|O_WRONLY|O_RDWR)) == O_RDONLY) { // values: 0, 1, 2
		open_mode = fstream::in;
	} else {
		open_mode = fstream::out;
		lseek(fd, 0, SEEK_END); // move position to end of file
	}

	std::fstream iofs;
	__gnu_cxx::stdio_filebuf<char> fbuf(fd, open_mode);
	iofs.std::ios::rdbuf(&fbuf);

	if (arg2 == 0) { // Read
		if ((open_flags & (O_RDONLY|O_WRONLY|O_RDWR)) == O_WRONLY) {
			cout << "cannot read from file opened write-only" << endl;
			return -1;
		}
		while (42) {
			string line;
			if (set_lock(fd, F_RDLCK))
				cout << "Error locking file: " << strerror(errno) << endl;
			if (!getline(iofs, line))
				break;
			set_lock(fd, F_UNLCK);
			cout << line << endl;
			sleep(1);
		}
	} else if (arg2 == 1) { // Write
		for (int i = 0; i < 100000; i++) {
			if (set_lock(fd, F_WRLCK))
				cout << "Error locking file: " << strerror(errno) << endl;
			for (int j = 0; j < 20; j++)
				iofs << j;
			iofs << endl;
			set_lock(fd, F_UNLCK);
			sleep(1);
		}
	} else {
		for (int i = 0; i < 100000; i++) {
			cout << "." << endl;
			sleep(1);
		}
	}
	iofs.close();

	return 0;
}
