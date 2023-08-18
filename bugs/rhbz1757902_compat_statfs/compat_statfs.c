/*
	compat_statfs.c - program to test that compat_statfs64() and compat_fstatfs(),
	compiled with _FILE_OFFSET_BITS=64, will not overflow 32-bit fields

	Frank Sorenson <sorenson@redhat.com>

	# mount -t tmpfs -o nr_inodes=4294967297 tmpfs /mnt
	# gcc compat_statfs.c -o compat_statfs -m32 -D_FILE_OFFSET_BITS=64
	# ./compat_statfs /mnt

	* compile-time error if the correct args are not passed when compiling
	* test setup error if none of the 64-bit fields would have overflowed
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#if __WORDSIZE != 32 || ! defined _FILE_OFFSET_BITS || _FILE_OFFSET_BITS != 64
#error "Compile with '-m32 -D_FILE_OFFSET_BITS=64"
#endif

int output_result(struct statfs stfs) {
	printf("  block count: 0x%016" PRIx64" (%" PRIu64 ")\n", (uint64_t)stfs.f_blocks, (uint64_t)stfs.f_blocks);
	printf("  blocks free: 0x%016" PRIx64" (%" PRIu64 ")\n", (uint64_t)stfs.f_bfree, (uint64_t)stfs.f_bfree);
	printf("  blocks available: 0x%016" PRIx64" (%" PRIu64 ")\n", (uint64_t)stfs.f_bavail, (uint64_t)stfs.f_bavail);

	printf("  file count: 0x%016" PRIx64 " - %" PRIu64 "\n", (uint64_t)stfs.f_files, (uint64_t)stfs.f_files);
	printf("  files free: 0x%016" PRIx64 " - %" PRIu64 "\n", (uint64_t)stfs.f_ffree, (uint64_t)stfs.f_ffree);
	if (!
		((stfs.f_blocks | stfs.f_bfree | stfs.f_bavail |
		 stfs.f_files | stfs.f_ffree) & __UINT64_C(0xffffffff00000000))) {
		printf("error in test setup: none of the 64-bit fields would overflow 32 bits\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
	struct statfs stfs;
	int err = 0;
	int fd;

	if (argc != 2) {
		printf("usage: %s <path>\n", argv[0]);
		return EXIT_FAILURE;
	}

	printf("testing statfs('%s'): ", argv[1]);

	if (statfs(argv[1], &stfs) < 0) {
		printf("statfs failed: %m\n");
		err++;
	} else {
		printf("statfs succeeded\n");
		if (output_result(stfs))
			err++;
	}

	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		printf("failed to open '%s': %m\n", argv[1]);
		err++;
	} else {
		printf("testing fstatfs(): ");
		if (fstatfs(fd, &stfs) < 0) {
			printf("fstatfs failed: %m\n");
			err++;
		} else {
			close(fd);

			printf("fstatfs succeeded\n");
			if (output_result(stfs))
				err++;
		}
	}
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}




