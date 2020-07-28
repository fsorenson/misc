CC=gcc
LIBS=

DEBUG=0

DEBUG_SYMBOLS=-g

CFLAGS= -Wall -DDEBUG=$(DEBUG) $(DEBUG_SYMBOLS) -fdiagnostics-color=always
SO_FLAGS= -shared -fPIC -rdynamic

all: blkio_ioctls2.so break_ioctls.so try_ioctl

SRCS=break_ioctls.c ptrace_defs.h
HDEPS=
#OBJS=$(SRCS:.[ch]=.o)
OBJS=

%.d: %.c %.h
	@mkdir -p $(@D)
	@$(SHELL) -ec '$(CC) -MM $(CPPFLAGS) %< > $@'

#-include $(deps)

try_ioctl: try_ioctl.c
	$(CC) try_ioctl.c -o try_ioctl -Wall -g

break_ioctls.so: $(SRCS) $(OBJS)
	$(CC) break_ioctls.c $(OBJS) -o break_ioctls.so $(CFLAGS) $(SO_FLAGS)

blkio_ioctls2.so: blkio_ioctls2.c
	$(CC) blkio_ioctls2.c -o blkio_ioctls2.so $(CFLAGS) $(SO_FLAGS) -ldl -g

clean:
	@rm break_ioctls.so blkio_ioctls2.so try_ioctl
