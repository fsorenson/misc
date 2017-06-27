#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include "test11_lib.h"

static Lmid_t namespace_id = 0;

struct obj_struct *get_new_obj(void) {
	void *dl_handle;
	char *error;
	void *ret = NULL;

//	if (dl_handle = dlopen("/home/sorenson/RH/case_remnants/C_object_testing/libtest11.so", RTLD_NOW | RTLD_DEEPBIND | RTLD_NODELETE)) {
	if (dl_handle = dlmopen(LM_ID_NEWLM, "/home/sorenson/RH/case_remnants/C_object_testing/libtest11.so", RTLD_LAZY | RTLD_DEEPBIND | RTLD_NODELETE)) {
		(void)dlerror();
		ret = dlsym(dl_handle, "__start_test11");
		error = dlerror();
		if (error != NULL) {
			ret = NULL;
			printf("dlsym error: %s\n", error);
		} else {
			if (dlinfo (dl_handle, RTLD_DI_LMID, &((struct obj_struct *)ret)->ns) != 0) {
				printf ("dlinfo for %s in %s failed: %s\n", "libtest11.so", __func__, dlerror());
			} else {
				printf("LM_ID is %d\n", ((struct obj_struct *)ret)->ns);
			}
		}
		dlclose(dl_handle);
	} else {
		printf("dlopen error: %s\n", dlerror());
	}
	return (struct obj_struct *)ret;
}

int main(int argc, char *argv[]) {
	char *error;
	char *p;

	int i;
	int ret;

	struct obj_struct *obj1;
	struct obj_struct *obj2;
	struct obj_struct *obj3;

	obj1 = get_new_obj();
	obj2 = get_new_obj();
	obj3 = get_new_obj();
	printf("obj1 = %p, obj2 = %p, obj3 = %p\n", obj1, obj2, obj3);



//	obj3_init

	obj1->set(88);
	obj1->print();


	printf("\n\nobj2: %p\n", obj2);
	obj2->print();
	obj2->set(11);
	obj2->print();


//	printf("About to initialize obj3\n");

//	obj3->init2(obj1, blob);
//	printf("returned from initializing obj3\n");
//	printf("obj1 = %p, obj1->trampolines = %p, obj3 = %p, obj3->trampolines = %p\n",
//		obj1, obj1->trampolines, obj3, obj3->trampolines);
//	printf("printf = %p, obj1->printf = %p, obj3->printf = %p\n",
//		&printf, obj1->trampolines.printf, obj3->trampolines.printf);




//	__init_test11_obj
//	new_obj_init(obj1, blob);


//	obj3->set = (set_func_t)((uint64_t)blob + (uint64_t)obj1->set - (uint64_t)obj1);
//	obj3->get = (get_func_t)((uint64_t)blob + (uint64_t)obj1->get - (uint64_t)obj1);
//	obj3->print = (print_func_t)((uint64_t)blob + (uint64_t)obj1->print - (uint64_t)obj1);

//	printf("in main(), printf is %p\n", &printf);
//	printf("about to print from obj3\n");
//	obj3->print();


	printf("obj1:\n");



	obj1->print();
	obj1->set(99);
	obj1->print();





	printf("obj2:\n");
	obj2->print();
	obj2->set(312);
	obj2->print();

	printf("size is %lu\n", obj1->size);
	printf("size of obj_struct is %lu\n", sizeof(struct obj_struct));



printf("obj1: %p, obj1->set: %p\n", obj1, obj1->set);
printf("obj2: %p, obj2->set: %p\n", obj2, obj2->set);
printf("obj3: %p, obj3->set: %p\n", obj3, obj3->set);


	get_addr_t get_printf_addr;

	obj3->print();
	obj3->set(4);
	obj3->print();


	printf("obj1:::\n");
	obj1->print();









	return EXIT_SUCCESS;
}
