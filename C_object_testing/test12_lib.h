#ifndef __TEST12_LIB_H__
#define __TEST12_LIB_H__

#ifndef __USE_GNU
#define __USE_GNU
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>


/* typedef the functions */
typedef unsigned long (*set_func_t)(unsigned long);
typedef unsigned long (*get_func_t)(void);
typedef void (*print_func_t)(void);

typedef uint64_t (*get_addr_t)(void);


struct obj_struct {
	uint64_t magic;

	uint64_t var;

	set_func_t set;
	get_func_t get;
	print_func_t print;

	void *start;
	void *stop;
	size_t size;
	Lmid_t ns; /* link map id/namespace */

	char blob[];
};


static inline struct obj_struct *new_obj(void) {
	void *dl_handle;
	char *error;
	void *ret = NULL;

//	if (dl_handle = dlopen("/home/sorenson/RH/case_remnants/C_object_testing/libtest12.so", RTLD_NOW | RTLD_DEEPBIND | RTLD_NODELETE)) {
	if (dl_handle = dlmopen(LM_ID_NEWLM, "/home/sorenson/RH/case_remnants/C_object_testing/libtest12.so", RTLD_LAZY | RTLD_DEEPBIND | RTLD_NODELETE)) {
		(void)dlerror();
		ret = dlsym(dl_handle, "__start_test12");
		error = dlerror();
		if (error != NULL) {
			ret = NULL;
			printf("dlsym error: %s\n", error);
		} else {
			if (dlinfo(dl_handle, RTLD_DI_LMID, &((struct obj_struct *)ret)->ns) != 0) {
				printf ("dlinfo for %s in %s failed: %s\n", "libtest12.so", __func__, dlerror());
			}
		}
		dlclose(dl_handle);
	} else {
		printf("dlopen error: %s\n", dlerror());
	}
	return (struct obj_struct *)ret;
}

#endif
