CC=gcc
LIBS = -lm
DEBUG_SYMBOLS=-g
CFLAGS = -Wall $(DEBUG_SYMBOLS) -fdiagnostics-color=always

ifeq "$(shell echo -e '\x23include <numa.h>\nint main(){return 0;}' | $(CC) -x c -Wall -lnuma -O -o /dev/null >/dev/null 2>/dev/null - && echo $$? )" "0"
#$(warning "found libnuma")
HAVE_LIBNUMA = -DHAVE_LIBNUMA=1
LIBS += -lnuma
else
$(warning "could not find libnuma")
HAVE_LIBNUMA =
endif

all: test_disk_writes

#SRCS = test_disk_writes.c

test_disk_writes: test_disk_writes.c
	$(CC) $(CFLAGS) $(LIBS) $(HAVE_LIBNUMA) $< -o $@

clean:
	@rm test_disk_writes
