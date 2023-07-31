#ifndef __ENCDEC_H__
#define __ENCDEC_H__

#include <stdbool.h>
#include "listxattr.h"

#define __PURE		__attribute__((pure))


#define ENCDEC_LIST_INCREMENT 5

#define ENCDEC_OPS \
	int (*init)(void); \
	int (*decode)(const char *attr_name, const unsigned char *attr_bytes, int len, bool is_dir); \
	int (*cleanup)(void);

#define ENCDEC_INIT_INFO \
	char *name; \
	char *description; \
	char *attr_string; \
	char *source_file; \
	char **xattr_strings

struct encdec_ops_struct {
	ENCDEC_OPS;
};

struct encdec_init_info_struct {
	ENCDEC_INIT_INFO;
};
struct encdec_info_struct {
	ENCDEC_OPS;
	ENCDEC_INIT_INFO;
	int index;
	bool initialized;
	char dummy1[16];
};

extern struct encdec_info_struct *encdec_info;
extern int encdec_count;

#define ADD_ENCDEC(encdec_name, _desc, ops, strings) \
	static char encdec_name_##encdec_name[] = #encdec_name; \
	static char encdec_description_##encdec_name[] = _desc; \
	static char encdec_source_file_##encdec_name[] = __FILE__; \
	static struct encdec_init_info_struct encdec_info_##encdec_name = { \
		.name = encdec_name_##encdec_name, \
		.description = encdec_description_##encdec_name, \
		.source_file = encdec_source_file_##encdec_name, \
		.xattr_strings = strings, \
	}; \
	void cons_encdec_type_##encdec_name(void) __attribute__((constructor)); \
	void cons_encdec_type_##encdec_name(void) { \
		encdec_add(encdec_name_##encdec_name); \
		encdec_do_initialization(&encdec_info_##encdec_name, ops); \
	} \
	static __attribute__((unused)) char encdec_init_dummy_##encdec_name

void encdec_do_initialization(struct encdec_init_info_struct *init_info, struct encdec_ops_struct *ops);
void encdec_mark_initialized(char *encdec_name);
void encdec_add(const char *encdec_name);

#endif
