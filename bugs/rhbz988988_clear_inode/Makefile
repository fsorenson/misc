obj-m += bz988988.o
KDIR= /lib/modules/$(shell uname -r)/build
all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	gcc bz988988_trunc.c -o bz988988_trunc

clean:
	rm -rf *.o *.ko* *.mod* .*cmd .t* [Mm]odule* bz988988_trunc test_file-*
