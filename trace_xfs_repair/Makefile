CC=gcc
LIBS=

DEBUG=1

DEBUG_SYMBOLS=-g

CFLAGS= -Wall -DDEBUG=$(DEBUG) $(DEBUG_SYMBOLS) -fdiagnostics-color=always
#SO_FLAGS= -shared -fPIC -rdynamic
SO_FLAGS=

all: trace_xfs_repair start_stopped

SRCS=trace_xfs_repair.c
HDEPS=misc.h
#OBJS=$(SRCS:.[ch]=.o)
OBJS=hexdump.o

%.d: %.c %.h
	@mkdir -p $(@D)
	@$(SHELL) -ec '$(CC) -MM $(CPPFLAGS) %< > $@'

#-include $(deps)

trace_xfs_repair: $(SRCS) $(OBJS)


hexdump.o: hexdump.c hexdump.h
	$(CC) -c hexdump.c -o hexdump.o $(CFLAGS) $(SO_FLAGS)

#fake_calls.o: fake_calls.c fake_calls.h sos_hooks.h $(HDEPS)
#	$(CC) -c fake_calls.c -o fake_calls.o $(CFLAGS) $(SO_FLAGS)

#sos_hooks.so: sos_hooks.c sos_hooks.h
#	$(CC) sos_hooks.c -o sos_hooks.so $(CFLAGS) $(SO_FLAGS)

#sos_hooks_lib.so: sos_hooks_lib.c sos_hooks.h
#	$(CC) sos_hooks_lib.c -o sos_hooks_lib.so $(CFLAGS) $(SO_FLAGS) -ldl

#sos_hooks_trimmed.so: sos_hooks_trimmed.c sos_hooks.h $(OBJS)
#	$(CC) sos_hooks_trimmed.c $(OBJS) -o sos_hooks_trimmed.so $(CFLAGS) $(SO_FLAGS)

clean:
	@rm trace_xfs_repair hexdump.o
#	@rm sos_hooks.so sos_hooks_lib.so sos_hooks_trimmed.so fake_calls.o
