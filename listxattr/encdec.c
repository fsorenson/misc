#include "encdec.h"
#include "listxattr.h"

struct encdec_info_struct *encdec_info = NULL;
int encdec_count = 0;

void __attribute__((destructor)) cleanup_encdec_info(void) {
	int i;

	free_mem(encdec_info);
	encdec_count = 0;
}
void encdec_add(const char *encdec_name) {
	unsigned long offset;
	unsigned long zero_address;
	unsigned long zero_size;


	if ((encdec_count % ENCDEC_LIST_INCREMENT) == 0) {
		void *ret = realloc(encdec_info, (unsigned long)(encdec_count + ENCDEC_LIST_INCREMENT) *
			sizeof(struct encdec_info_struct));
		if (ret == NULL)
			exit_fail("unable to allocate memory\n");
		if (errno)
			exit_fail("errno is nonzero: %m\n");
		encdec_info = (struct encdec_info_struct *)ret;

		offset = sizeof(struct encdec_info_struct) * ((unsigned long)encdec_count);
		zero_address = (unsigned long)(char *)encdec_info + offset;
		zero_size = sizeof(struct encdec_info_struct) * ENCDEC_LIST_INCREMENT;

		ret = memset((void *)zero_address, 0, zero_size);
		if (ret != (void *)zero_address) {
			output("somethin' fishy... expected 0x%08lx to equal 0x%08lx\n",
				(unsigned long)ret, zero_address);
		}
	}

	encdec_info[encdec_count].name = encdec_name;
	encdec_info[encdec_count].index = encdec_count;
	encdec_info[encdec_count].initialized = false;

	encdec_count++;
}
void encdec_mark_initialized(char *encdec_name) {
	int i;

	for (i = 0 ; i < encdec_count ; i++) {
		if (strcmp(encdec_info[i].name, encdec_name) == 0) {
			encdec_info[i].initialized = true;
			return;
		}
	}
	output("error: unable to initialize unknown encdec type '%s'\n", encdec_name);
}
void encdec_do_initialization(struct encdec_init_info_struct *init_info, struct encdec_ops_struct *ops) {
	int i;

	for (i = 0 ; i < encdec_count ; i++) {
		if (!strcmp(encdec_info[i].name, init_info->name)) {
			if (init_info->description)
				encdec_info[i].description = init_info->description;
			encdec_info[i].init = ops->init ? ops->init : NULL;
			encdec_info[i].cleanup = ops->cleanup ? ops->cleanup : NULL;
			encdec_info[i].decode = ops->decode ? ops->decode : NULL;
			encdec_info[i].xattr_strings = init_info->xattr_strings;

			encdec_info[i].initialized = true;
			return;
		}
	}
	output("error: unable to initialize unknown encdec type '%s'\n", init_info->name);
}

char * __PURE get_encdec_name(int index) {
	return encdec_info[index].name;
}
