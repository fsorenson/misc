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
#include "test12_lib.h"

int main(int argc, char *argv[]) {
	char *error;
	char *p;

	int i;
	int ret;

	struct obj_struct *obj1;
	struct obj_struct *obj2;
	struct obj_struct *obj3;

	obj1 = new_obj();
	obj2 = new_obj();
	obj3 = new_obj();
	printf("obj1 = %p, obj2 = %p, obj3 = %p\n", obj1, obj2, obj3);

	printf("obj1: %p, obj1->set: %p\n", obj1, obj1->set);
	printf("obj2: %p, obj2->set: %p\n", obj2, obj2->set);
	printf("obj3: %p, obj3->set: %p\n", obj3, obj3->set);


	obj1->set(88);
	obj1->print();

	printf("\n\nobj2: %p\n", obj2);
	obj2->print();
	obj2->set(12);
	obj2->print();

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

	obj3->print();
	obj3->set(4);
	obj3->print();

	printf("obj1:::\n");
	obj1->print();


	return EXIT_SUCCESS;
}
