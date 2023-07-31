/*
	Frank Sorenson <sorenson@redhat.com>, 2023


	Display xattrs attached to a file/directory,
	and decode as many of them as possible

*/

#ifndef __UNIMPLEMENTED_H__
#define __UNIMPLEMENTED_H__

#include "encdec.h"

int decode_unimplemented(const char *xattr_name, const unsigned char *attr, int attr_len, bool is_dir);

#endif
