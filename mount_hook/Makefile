obj-m += mount_hook.o
KDIR = /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf *.o *.ko* *.mod* .*cmd .t* [Mm]odule*
