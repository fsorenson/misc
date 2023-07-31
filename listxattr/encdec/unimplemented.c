/*
	Frank Sorenson <sorenson@redhat.com>, 2016


	Display xattrs attached to a file/directory,
	and decode as many of them if possible

*/

#include "selinux.h"

int decode_unimplemented(const char *xattr_name, const unsigned char *xattr, int attr_len, bool is_dir) {
	output("sorry, '%s' not implemented\n", xattr_name);

	return EXIT_SUCCESS;
}

static char *unimplemented_xattrs[] = {
	XATTR_NAME_SMACK,
	XATTR_NAME_SMACKIPIN,
	XATTR_NAME_SMACKIPOUT,
	XATTR_NAME_SMACKEXEC,
	XATTR_NAME_SMACKTRANSMUTE,
	XATTR_NAME_SMACKMMAP,

	XATTR_NAME_APPARMOR,

	XATTR_NAME_IMA,

	NULL,
};

static struct encdec_ops_struct encdec_unimplemented_ops = {
	.decode = decode_unimplemented,
};

ADD_ENCDEC(unimplemented, "unimplemented", &encdec_unimplemented_ops, unimplemented_xattrs);
