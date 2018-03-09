obj-m += proclocks2.o
UNAME_R= $(shell uname -r)
UNAME_P= $(shell uname -p)
UNAME_NOARCH= $(shell basename -s .$(UNAME_P) $(UNAME_R))
KDIR= /lib/modules/$(UNAME_R)/build

KDEBDIR= /usr/src/debug/kernel-$(UNAME_NOARCH)/linux-$(UNAME_R)/

#/usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/nfsd/state.h


all:
	ln -sf $(KDEBDIR)/fs/nfsd/state.h nfsd_state.h
	ln -sf $(KDEBDIR)/fs/nfsd/nfsfh.h nfsfh.h
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf *.o *.ko* *.mod* .*cmd .t* [Mm]odule* test_file-* nfsd_state.h nfsfh.h
