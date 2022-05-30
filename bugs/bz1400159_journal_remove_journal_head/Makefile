obj-m += bz1400159.o
KDIR= /lib/modules/$(shell uname -r)/build
all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf *.o *.ko* *.mod* .*cmd .t* [Mm]odule* test_file-*
