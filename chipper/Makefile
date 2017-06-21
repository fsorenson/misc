CC=gcc

BUILD_DEBUG=1
BUILD_SHARED=0

DEBUG_FLAGS=
ASFLAGS=
ASFLAGS_LIB=
LDFLAGS= -lm
LDFLAGS_LIB= -lm

_all=mulch
ifeq ($(BUILD_DEBUG),1)
  CFLAGS += -D DEBUG=0 -g -gstabs+ -gno-strict-dwarf -Wa,--gdwarf-sections -grecord-gcc-switches
  DEBUG_FLAGS += -ggdb3 -fverbose-asm


  ASFILE_LIB=libchipper.s
  ASFLAGS_LIB += -Wa,-aghlms=$(ASFILE_LIB) -Wa,-L
  ASFILE=mulch.s
  ASFLAGS += -Wa,-aghlms=$(ASFILE)


  MAPFILE_LIB=libchipper.map
#  LDFLAGS_LIB += -Wl,--cref -Wl,-Map=$(MAPFILE_LIB) -ldl -Wl,--unique
  LDFLAGS_LIB += -Wl,--cref -Wl,-Map=$(MAPFILE_LIB) -ldl
  MAPFILE=mulch.map
#  LDFLAGS += -Wl,-M -Wl,--cref -Wl,-Map=$(MAPFILE) -Wl,--unique
  LDFLAGS += -Wl,-M -Wl,--cref -Wl,-Map=$(MAPFILE)


else
  CFLAGS += -D DEBUG=0
endif


ifeq ($(BUILD_SHARED),1)
  LDFLAGS_SHARED=-L /home/sorenson/RH/case_remnants/chipper -lchipper
  _all += libchipper.so mulch-shared
endif

WARNINGS=-Wall -Wextra -Winit-self -Wwrite-strings -Wunused-parameter -Wundef -Wtrampolines
DIAGNOSTICS=-fdiagnostics-show-location=every-line -fdiagnostics-show-option -fvar-tracking-assignments -frecord-gcc-switches

CFLAGS += $(WARNINGS) $(DEBUG_FLAGS) $(DIAGNOSTICS)


all: $(_all)

clean:
	rm -f libchipper.so chipper.o mulch mulch-shared libchipper.s libchipper.map mulch.s mulch.map


libchipper.so: libchipper.c libchipper.h
	gcc -ggdb3 libchipper.c -o libchipper.so -shared -rdynamic -fpic -fms-extensions $(ASFLAGS_LIB) $(LDFLAGS_LIB) -D BUILD_SHARED=1 $(CFLAGS)

mulch-shared: mulch.c libchipper.so
	gcc -ggdb3 mulch.c -o mulch-shared -ldl $(CFLAGS) $(ASFLAGS) $(LDFLAGS) $(LDFLAGS_SHARED)



chipper.o: libchipper.c libchipper.h
	gcc -ggdb3 libchipper.c -c -o chipper.o -fms-extensions $(ASFLAGS_LIB) $(LDFLAGS_LIB) -D BUILD_SHARED=0 $(CFLAGS) -Wl,-N -Wl,-relax -Wl,-q -Wl,-Bsymbolic-functions -Wa,-aghlms=chipper.s
#	gcc -ggdb3 libchipper.c -c -o chipper.o -fms-extensions $(ASFLAGS_LIB) $(LDFLAGS_LIB) -D BUILD_SHARED=0 $(CFLAGS) -Wl,-Bsymbolic-functions -Wl,-relax -Wl,-q -mcmodel=large -N

mulch: mulch.c chipper.o
	gcc -ggdb3 mulch.c chipper.o -o mulch $(CFLAGS) $(ASFLAGS) $(LDFLAGS) -Wl,-Bsymbolic-functions -Wl,-relax -Wl,-q

