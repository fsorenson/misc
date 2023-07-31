/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them if possible

*/

#include "selinux.h"

static int init_selinux(void) {
	printf("in %s\n", __func__);
	return EXIT_SUCCESS;
}


int decode_selinux(const char *xattr_name, const unsigned char *xattr, int attr_len, bool is_dir) {
	printf("\t%s\n", xattr);

	return EXIT_SUCCESS;
}

static char *selinux_xattrs[] = {
	"security.selinux",
	NULL,
};

static struct encdec_ops_struct encdec_selinux_ops = {
	.init = init_selinux,
	.decode = decode_selinux,
	.cleanup = NULL,
};

ADD_ENCDEC(selinux, "selinux", &encdec_selinux_ops, selinux_xattrs);
