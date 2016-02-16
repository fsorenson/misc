CC=gcc
LIBS=-lacl

CFLAGS= -Wall

all: listxattr

SRCS=listxattr.c listxattr.h lib.c lib.h ext.c ext.h nfs4.c nfs4.h
#OBJS=$(SRCS:.[ch]=.o)
OBJS=listxattr.o lib.o ext.o nfs4.o

lib.o: lib.c lib.h
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

listxattr.o: listxattr.c listxattr.h
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

ext.o: ext.c ext.h
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

nfs4.o: nfs4.c nfs4.h
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@


listxattr:	$(OBJS)
	$(CC) -o $@ $(OBJS) $(CFLAGS) $(LIBS)

#.c.o:
#	$(CC) -c $(CFLAGS) $(INCLUDES) $<

clean:
	@rm listxattr
