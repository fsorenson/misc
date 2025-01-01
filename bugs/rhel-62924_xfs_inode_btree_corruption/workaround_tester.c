#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <xfs/xfs.h>
#include <linux/magic.h>

int xfs_ag_count(int fd) {
	struct xfs_fsop_geom fsgeo;

	memset(&fsgeo, 0, sizeof(fsgeo));
	if (ioctl(fd, XFS_IOC_FSGEOMETRY, &fsgeo) == 0)
		return fsgeo.agcount;
#ifdef XFS_IOC_FSGEOMETRY_V4
	if (ioctl(fd, XFS_IOC_FSGEOMETRY_V4, &fsgeo) == 0)
		return fsgeo.agcount;
#endif
	if (ioctl(fd, XFS_IOC_FSGEOMETRY_V1, &fsgeo) == 0)
		return fsgeo.agcount;
	printf("error getting AG count: %m\n");
	return 0;
}

int write_and_close_fd(int fd) {
	const char *buf = "testing\n";

	if (fd >= 0 && write(fd, buf, sizeof(buf)) == sizeof(buf) && close(fd) == 0) {
		printf(" - success\n");
		return 0;
	}
	printf(" - error: %m\n");
	return 1;
}

#define assemble_path(_msg, args...) do { \
	snprintf(test_path_str, path_max - 1, args); \
	printf("  %s: %s", _msg, test_path_str); \
} while (0)

#define try_func(_func, args...) do { \
	if (_func(args) < 0) { \
		errs++; \
		printf(" - failure: %m\n"); \
	} else \
		printf(" - success\n"); \
} while (0);

int test_dir_path(const char *dir_path) {
	char *test_path_str = NULL, *buf = "testing\n";
	int path_max, errs = 0, dfd = -1, agcount, i;
	struct statfs stfs;
	struct stat st;
	FILE *fp;

	printf("path: %s\n", dir_path);

	if (dir_path[0] != '/') {
		printf("  please provide absolute pathname\n");
		errs++;
		goto out;
	}
	if (stat(dir_path, &st) < 0) {
		if (errno == ENOENT)
			printf("  test directory '%s' does not exist\n", dir_path);
		else
			printf("  error accessing test directory '%s': %m\n", dir_path);
		errs++;
		goto out;
	}
	if (!S_ISDIR(st.st_mode)) {
		printf("  cannot create files in non-directory '%s'\n", dir_path);
		errs++;
		goto out;
	}
	if (statfs(dir_path, &stfs) < 0) {
		printf("  error getting filesystem information: %m\n");
		errs++;
		goto out;
	}
	if (stfs.f_type != XFS_SUPER_MAGIC) {
		printf("  directory '%s' is not on an XFS filesystem\n", dir_path);
		errs++;
		goto out;
	}

	if ((dfd = open(dir_path, O_DIRECTORY|O_RDONLY)) < 0) {
		printf("  error opening directory: %m\n");
		errs++;
		goto out;
	}
	agcount = xfs_ag_count(dfd);

	path_max = pathconf(dir_path, _PC_PATH_MAX);
	test_path_str = malloc(path_max);

	printf("  path is on XFS filesystem with %d AGs\n", agcount);

	// test absolute paths
	assemble_path(  "creat() absolute path", "%s/testfile_creat_absolute", dir_path);
//	snprintf(test_path_str, path_max - 1, "%s/testfile_creat_absolute", dir_path);
//	printf("  creat() absolute path: %s", test_path_str);
	errs += write_and_close_fd(creat(test_path_str, 0644));

	assemble_path("  open() absolute path", "%s/testfile_open_absolute", dir_path);
//	snprintf(test_path_str, path_max - 1, "%s/testfile_open_absolute", dir_path);
//	printf("  open() absolute path: %s", test_path_str);
	errs += write_and_close_fd(open(test_path_str, O_CREAT|O_TRUNC|O_WRONLY, 0644));

//	snprintf(test_path_str, path_max - 1, "%s/testfile_open64_absolute", dir_path);
//	printf("  open64() absolute path: %s", test_path_str);
	assemble_path("  open64() absolute path", "%s/testfile_open64_absolute", dir_path);
	errs += write_and_close_fd(open64(test_path_str, O_CREAT|O_TRUNC|O_WRONLY, 0644));

//	snprintf(test_path_str, path_max - 1, "%s/testfile_openat_absolute_AT_FDCWD", dir_path);
//	printf("  openat() absolute path (using AT_FDCWD): %s", test_path_str);
	assemble_path("  openat() absolute path (using AT_FDCWD)", "%s/testfile_openat_absolute_AT_FDCWD", dir_path);
	errs += write_and_close_fd(openat(AT_FDCWD, test_path_str, O_CREAT|O_TRUNC|O_WRONLY, 0644));

//	snprintf(test_path_str, path_max - 1, "%s/testfile_openat_absolute_dfd", dir_path);
//	printf("  openat() absolute path (using dfd): %s", test_path_str);
	assemble_path("  openat() absolute path (using dfd)", "%s/testfile_openat_absolute_dfd", dir_path);
	errs += write_and_close_fd(openat(dfd, test_path_str, O_CREAT|O_TRUNC|O_WRONLY, 0644));

//	snprintf(test_path_str, path_max - 1, "%s/testfile_openat64_absolute_AT_FDCWD", dir_path);
//	printf("  openat64() absolute path (using AT_FDCWD): %s", test_path_str);
	assemble_path("  openat64() absolute path (using AT_FDCWD)", "%s/testfile_openat64_absolute_AT_FDCWD", dir_path);
	errs += write_and_close_fd(openat64(AT_FDCWD, test_path_str, O_CREAT|O_TRUNC|O_WRONLY, 0644));

//	snprintf(test_path_str, path_max - 1, "%s/testfile_openat64_absolute_dfd", dir_path);
//	printf("  openat64() absolute path (using dfd): %s", test_path_str);
	assemble_path("  openat64() absolute path (using dfd)", "%s/testfile_openat64_absolute_dfd", dir_path);
	errs += write_and_close_fd(openat64(dfd, test_path_str, O_CREAT|O_TRUNC|O_WRONLY, 0644));


//	snprintf(test_path_str, path_max - 1, "%s/testfile_fopen_absolute", dir_path);
//	printf("  fopen() absolute path: %s", test_path_str);
	assemble_path("  fopen() absolute path", "%s/testfile_open_absolute", dir_path);
	if ((fp = fopen(test_path_str, "w")) == NULL) {
		errs++;
		printf(" - error: %m\n");
	} else {
		if (fwrite(buf, 1, sizeof(buf), fp) != sizeof(buf) || fclose(fp) != 0) {
			errs++;
			printf(" - error: %m\n");
		} else
			printf(" - success\n");
	}

	printf("  attempting %d mkdir calls\n", agcount);
	for (i = 0 ; i < agcount ; i++) {
		assemble_path("  mkdir() absolute path", "%s/testdir_mkdir_absolute_%d", dir_path, i);
		try_func(mkdir, test_path_str, 0755);
	}

	printf("  attempting %d mkdirat calls\n", agcount);
	for (i = 0 ; i < agcount ; i++) {
		assemble_path("  mkdirat() absolute path", "%s/testdir_mkdirat_absolute_%d", dir_path, i);
		try_func(mkdirat, AT_FDCWD, test_path_str, 0755);
	}

	assemble_path("  symlink() absolute path", "%s/test_symlink_absolute", dir_path);
	try_func(symlink, "/", test_path_str);

	assemble_path("  symlinkat() absolute path (using AT_FDCWD)", "%s/test_symlinkat_absolute_AT_FDCWD", dir_path);
	try_func(symlinkat, "/", AT_FDCWD, test_path_str);

	assemble_path("  symlinkat() absolute path (using dfd)", "%s/test_symlinkat_absolute_dfd", dir_path);
	try_func(symlinkat, "/", dfd, test_path_str);


	assemble_path("  mknod(/dev/null) (char 1:3)", "%s/test_mknod_devnull_char.1.3_absolute", dir_path);
	try_func(mknod, test_path_str, S_IFCHR | 0666, makedev(1, 3));

	assemble_path("  mknod(/dev/vda) (block 252:0)", "%s/test_mknod_devvda_block.252.0_absolute", dir_path);
	try_func(mknod, test_path_str, S_IFBLK | 0600, makedev(252, 0));
	assemble_path("  mknodat(/dev/vda) (block 252:0)", "%s/test_mknodat_devvda_block.252.0_absolute", dir_path);
	try_func(mknodat, AT_FDCWD, test_path_str, S_IFBLK | 0600, makedev(252, 0));

	assemble_path("  mknod(named_pipe)", "%s/test_mknod_named_pipe_absolute", dir_path);
	try_func(mknod, test_path_str, S_IFIFO | 0666, 0);

//	there is no mknodat library function
//	assemble_path("  mknodat(named_pipe)", "%s/test_mknodat_named_pipe_absolute", dir_path);
//	try_func(mknodat, AT_FDCWD, test_path_str, S_IFIFO | 0666, 0);

	assemble_path("  mkfifo(named_pipe)", "%s/test_mkfifo_named_pipe_absolute", dir_path);
	try_func(mkfifo, test_path_str, 0666);

	assemble_path("  mkfifoat(named_pipe)", "%s/test_mkfifoat_named_pipe_absolute", dir_path);
	try_func(mkfifoat, AT_FDCWD, test_path_str, 0666);

//	assemble_path("  mkostemps()", "%s/test_mkostemps_XXXXXX_suffix_absolute", dir_path);
//	try_func(mkostemps, test_path_str, 7, 0);


	// test relative paths
	chdir(dir_path);

	assemble_path("  creat() relative path", "%s", "testfile_creat_relative");
	errs += write_and_close_fd(creat(test_path_str, 0644));

	assemble_path("  open() relative path", "%s", "testfile_open_relative");
	errs += write_and_close_fd(open(test_path_str, O_CREAT|O_TRUNC|O_WRONLY, 0644));

	assemble_path("  open64() relative path", "%s", "testfile_open64_relative");
	errs += write_and_close_fd(open64(test_path_str, O_CREAT|O_TRUNC|O_WRONLY, 0644));

	assemble_path("  openat() relative path (using AT_FDCWD)", "%s", "testfile_openat_relative_AT_FDCWD");
	errs += write_and_close_fd(openat(AT_FDCWD, test_path_str, O_CREAT|O_TRUNC|O_WRONLY, 0644));

	assemble_path("  openat() relative path (using dfd)", "%s", "testfile_openat_relative_dfd");
	errs += write_and_close_fd(openat(dfd, test_path_str, O_CREAT|O_TRUNC|O_WRONLY, 0644));

	assemble_path("  openat64() relative path (using AT_FDCWD)", "%s", "testfile_openat64_relative_AT_FDCWD");
	errs += write_and_close_fd(openat64(AT_FDCWD, test_path_str, O_CREAT|O_TRUNC|O_WRONLY, 0644));

	assemble_path("  openat64() relative path (using dfd)", "%s", "testfile_openat64_relative_dfd");
	errs += write_and_close_fd(openat64(dfd, test_path_str, O_CREAT|O_TRUNC|O_WRONLY, 0644));

	assemble_path("  fopen() relative path", "%s", "testfile_fopen_relative");
	if ((fp = fopen(test_path_str, "w")) == NULL) {
		errs++;
		printf(" - error: %m\n");
	} else {
		if (fwrite(buf, 1, sizeof(buf), fp) != sizeof(buf) || fclose(fp) != 0) {
			errs++;
			printf(" - error: %m\n");
		} else
			printf(" - success\n");
	}

	printf("  attempting %d mkdir calls\n", agcount);
	for (i = 0 ; i < agcount ; i++) {
		assemble_path("    mkdir() relative path", "testdir_mkdir_relative_%d", i);
		try_func(mkdir, test_path_str, 0755);
	}

	printf("  attempting %d mkdirat calls\n", agcount);
	for (i = 0 ; i < agcount ; i++) {
		assemble_path("    mkdirat() relative path (using AT_FDCWD)", "testdir_mkdir_relative_AT_FDCWD_%d", i);
		try_func(mkdirat, AT_FDCWD, test_path_str, 0755);
	}
	printf("  attempting %d mkdirat calls\n", agcount);
	for (i = 0 ; i < agcount ; i++) {
		assemble_path("  mkdirat() relative path (using dfd)", "testdir_mkdirat_relative_dfd_%d", i);
		try_func(mkdirat, dfd, test_path_str, 0755);
	}

	assemble_path("  symlink() relative path", "%s", "test_symlink_relative");
	try_func(symlink, "/", test_path_str);

	assemble_path("  symlinkat() relative path (using AT_FDCWD)", "%s", "test_symlinkat_relative_AT_FDCWD");
	try_func(symlinkat, "/", AT_FDCWD, test_path_str);

	assemble_path("  symlinkat() relative path (using dfd:)", "%s", "test_symlinkat_relative_dfd");
	try_func(symlinkat, "/",dfd, test_path_str);


	assemble_path("  mknod(/dev/null) (char 1:3)", "test_mknod_devnull_char.1.3_relative");
	try_func(mknod, test_path_str, S_IFCHR | 0666, makedev(1, 3));

	assemble_path("  mknod(/dev/vda) (block 252:0)", "test_mknod_devvda_block.252.0_relative");
	try_func(mknod, test_path_str, S_IFBLK | 0600, makedev(252, 0));

	assemble_path("  mknod(named_pipe)", "test_mknod_named_pipe_relative");
	try_func(mknod, test_path_str, S_IFIFO | 0666, 0);

//	there is no mknodat library function
//	assemble_path("  mknodat(named_pipe)", "test_mknodat_named_pipe_relative");
//	try_func(mknodat, AT_FDCWD, test_path_str, S_IFIFO | 0666, 0);

	assemble_path("  mkfifo(named_pipe)", "test_mkfifo_named_pipe_relative");
	try_func(mkfifo, test_path_str, 0666);

	assemble_path("  mkfifoat(named_pipe)", "test_mkfifoat_named_pipe_relative");
	try_func(mkfifoat, AT_FDCWD, test_path_str, 0666);

//	assemble_path("  mkostemps() relative", "test_mkostemps_XXXXXX_suffix_relative");
//	try_func(mkostemps, test_path_str, 7, 0);

out:
	if (test_path_str)
		free(test_path_str);
	if (dfd > 0)
		close(dfd);

	return errs;
}

int main(int argc, char *argv[]) {
	int i, errs = 0;

	if (argc < 2) {
		printf("usage: %s <subdir>\n", argv[0]);
		errs++;
		goto out;
	}

	for (i = 1 ; i < argc ; i++)
		errs += test_dir_path(argv[i]);

out:
	if (errs) {
		printf("%d errors noted\n", errs);
		return EXIT_FAILURE;
	} else
		return EXIT_SUCCESS;
}
