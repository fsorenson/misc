/*
	Frank Sorenson <sorenson@redhat.com>
	Red Hat, 2016

	# gcc cifs_securityflags.c -o cifs_securityflags

	usage
	# cifs_securityflags [<security_flag_value>]

	if no argument is provided, security flags will
	be read from /proc/fs/cifs/SecurityFlags

	otherwise, the value provided will be decoded
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#define BUF_LEN 4096

struct security_flag_pairs {
	char *flavor;
	uint32_t may;
	uint32_t must;
};

struct security_flag_pairs cifs_flags[] = {
	{ "SIGN", 0x00001, 0x01001 },
	{ "NTLM", 0x00002, 0x02002 },
	{ "NTLMV2", 0x00004, 0x04004 },
	{ "KRB5", 0x00008, 0x08008 },
	{ "LANMAN", 0x00010, 0x10010 },
	{ "PLNTXT", 0x00020, 0x20020 },
	{ "SEAL", 0x00040, 0x40040 },
	{ "NTLMSSP", 0x00080, 0x80080 },
	{ 0, 0, 0 }
};

void decode_cifs_flags(uint32_t flags) {
	uint32_t i = 0, count = 0;
	char *str;

	while (cifs_flags[i].flavor != 0) {
		if ((flags & cifs_flags[i].must) == cifs_flags[i].must) str = "MUST";
		else if ((flags & cifs_flags[i].may) == cifs_flags[i].may) str = "MAY";
		else str = "____";
		printf("%s: %s\n", cifs_flags[i].flavor, str);
		i++;
	}
}

int main(int argc, char *argv[]) {
	char buf[BUF_LEN];
	uint32_t secFlags;
	int ret, fd;

	if (argc == 1) {
		if ((fd = open("/proc/fs/cifs/SecurityFlags", O_RDONLY)) < 0) {
			printf("error opening /proc/fs/cifs/SecurityFlags: %m\n");
			return EXIT_FAILURE;
		}
		ret = read(fd, buf, BUF_LEN);
		close(fd);

		while (buf[ret-- - 1] == '\n')
			buf[ret] = '\0';
	} else if (argc == 2)
		strncpy(buf, argv[1], BUF_LEN);

	secFlags = strtol(buf, NULL, 16);

	printf("secFlags is 0x%x\n", secFlags);
	decode_cifs_flags(secFlags);

	return EXIT_SUCCESS;
}
