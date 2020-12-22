CC=gcc
LIBS=

DEBUG=1

DEBUG_SYMBOLS=-g

CFLAGS= -Wall -DDEBUG=$(DEBUG) $(DEBUG_SYMBOLS) -fdiagnostics-color=always
SO_FLAGS= -shared -fPIC -rdynamic

all: ptrace_mount.so hook_lib.so

SRCS=ptrace_mount.c
HDEPS=
#OBJS=$(SRCS:.[ch]=.o)
OBJS=fake_calls.o

%.d: %.c %.h
	@mkdir -p $(@D)
	@$(SHELL) -ec '$(CC) -MM $(CPPFLAGS) %< > $@'

#-include $(deps)


hexdump.o: hexdump.c hexdump.h
	$(CC) -c hexdump.c -o hexdump.o $(CFLAGS) $(SO_FLAGS)

fake_calls.o: fake_calls.c fake_calls.h ptrace_mount.h $(HDEPS)
	$(CC) -c fake_calls.c -o fake_calls.o $(CFLAGS) $(SO_FLAGS)

sos_hooks.so: sos_hooks.c sos_hooks.h
	$(CC) sos_hooks.c -o sos_hooks.so $(CFLAGS) $(SO_FLAGS)

hook_lib.so: hook_lib.c ptrace_mount.h
	$(CC) hook_lib.c -o hook_lib.so $(CFLAGS) $(SO_FLAGS) -ldl

ptrace_mount.so: ptrace_mount.c ptrace_mount.h $(OBJS)
	$(CC) ptrace_mount.c $(OBJS) -o ptrace_mount.so $(CFLAGS) $(SO_FLAGS)

clean:
	@rm ptrace_mount.so ptrace_mount_lib.so fake_calls.o
