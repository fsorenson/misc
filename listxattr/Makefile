CC=gcc
LIBS=-lacl

current_dir = $(shell pwd)

CFLAGS= -Wall -g
CFLAGS += -I$(current_dir) -I$(current_dir)/encdec

all: listxattr

SRCS=listxattr.c listxattr.h lib.h lib.c
SRCS += posix.h posix.c
SRCS += ext.h ext.c
SRCS += xfs.h xfs.c
SRCS += nfs4.h nfs4.c
SRCS += ntacl.h ntacl.c
SRCS += selinux.h selinux.c
SRCS += capability.h capability.c

#OBJS=$(SRCS:.[ch]=.o)
OBJS=listxattr.o lib.o
OBJS += posix.o ext.o xfs.o nfs4.o ntacl.o selinux.o capability.o encdec.o


lib.o: lib.c lib.h
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

listxattr.o: listxattr.c listxattr.h
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

#ext.o: ext.c ext.h
#	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

#nfs4.o: nfs4.c nfs4.h
#	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@


listxattr:	$(OBJS)
	$(CC) -o $@ $(OBJS) $(CFLAGS) $(LIBS)

#.c.o:
#	$(CC) -c $(CFLAGS) $(INCLUDES) $<

clean:
	@rm listxattr $(OBJS)
