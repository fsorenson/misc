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


encdec_dir = encdec
encdec_objs_dir = objs
encdec_deps_dir = deps
encdec_c_srcs = $(wildcard $(encdec_dir)/*.c)
encdecs = $(notdir $(basename $(encdec_c_srcs)))
encdecs_deps = $(addprefix $(encdec_deps_dir)/, $(addsuffix .d, $(encdecs)))

encdec_objs = $(addprefix $(encdec_objs_dir)/, $(addsuffix .o, $(encdecs)))
encdec_objs += lib.o encdec.o

$(encdec_objs_dir)/%.o: $(encdec_dir)/%.c $(encdec_dir)/%.h $(encdec_deps_dir)/%.d
	@mkdir -p $(@D)
	$(info CFLAGS is $(CFLAGS))
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -c $< -o $@

lib.o: lib.c lib.h
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

listxattr.o: listxattr.c listxattr.h
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

#ext.o: ext.c ext.h
#	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

#nfs4.o: nfs4.c nfs4.h
#	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@


listxattr: $(encdec_objs) $(OBJS)
	$(CC) -o $@ $(encdec_objs) $(OBJS) $(CFLAGS) $(LIBS)

#.c.o:
#	$(CC) -c $(CFLAGS) $(INCLUDES) $<

clean:
	@rm listxattr $(OBJS)
