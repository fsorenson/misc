CC=gcc
LIBS = -lpcre

DEBUG_SYMBOLS=-g
CFLAGS = -Wall $(DEBUG_SYMBOLS) -fdiagnostics-color=always



all: strace-tk2

SRCS = strace-tk2.c
OBJS =

strace-tk2: $(SRCS) $(OBJS)
	$(CC) strace-tk2.c -o strace-tk2 $(CFLAGS) $(SO_FLAGS) $(LIBS)

