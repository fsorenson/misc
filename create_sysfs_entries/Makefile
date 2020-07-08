obj-m += sysfs_entries.o
KDIR= /lib/modules/$(shell uname -r)/build
#KDIR= /root/linux/
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.o *.ko* *.mod* .*cmd .t* [Mm]odule*
