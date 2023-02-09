#ifndef __HEXDUMP_H__
#define __HEXDUMP_H__

#include <stddef.h>

#include "common.h"

void hexdump(const char *pre, const char *addr, size_t len);

#endif
