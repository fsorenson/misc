CC=gcc

BUILD_SHARED=0
USE_INDIRECTS=0

DEBUG_FLAGS=
ASFLAGS=
ASFLAGS_LIB=
LDFLAGS= -lm -lrt
LDFLAGS_LIB= -lm -lrt

_all=mulch
CFLAGS = 
CFLAGS += -gno-strict-dwarf -fno-omit-frame-pointer

# doesn't work in rhel6
#CFLAGS += -grecord-gcc-switches -Wa,--gdwarf-sections
DEBUG_FLAGS += -g3 -ggdb3 -fverbose-asm -fno-omit-frame-pointer


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



ifeq ($(BUILD_SHARED),1)
  LDFLAGS_SHARED=-L /home/sorenson/RH/case_remnants/chipper -lchipper
  _all += libchipper.so mulch-shared
endif

WARNINGS=-Wall -Wextra -Winit-self -Wwrite-strings -Wunused-parameter -Wundef

# doesn't work in rhel6
#WARNINGS+=-Wtrampolines
DIAGNOSTICS=-fdiagnostics-show-location=every-line -fdiagnostics-show-option -fvar-tracking -fvar-tracking-assignments

# doesn't work in rhel6
#DIAGNOSTICS+=-frecord-gcc-switches
#EXTRAS = -fstack-usage

CFLAGS += $(WARNINGS) $(DEBUG_FLAGS) $(DIAGNOSTICS)


all: $(_all)

clean:
	rm -f libchipper.so chipper.o mulch mulch-shared libchipper.s libchipper.map mulch.s mulch.map




libchipper.so: libchipper.c libchipper.h
	gcc -ggdb3 libchipper.c -o libchipper.so -shared -rdynamic -fPIC -fms-extensions $(ASFLAGS_LIB) $(LDFLAGS_LIB) -D BUILD_SHARED=1 -D USE_INDIRECTS=$(USE_INDIRECTS) $(CFLAGS)

mulch-shared: mulch.c libchipper.so
	gcc -ggdb3 mulch.c -o mulch-shared -ldl $(CFLAGS) $(ASFLAGS) $(LDFLAGS) $(LDFLAGS_SHARED)


wrapfunc_offsets.h: wrapfunc_gen_offsets.c wrapfunc.h
	gcc -S wrapfunc_gen_offsets.c -o - | awk '{if ($$1 == "->") {print "#define "$$2" __STR("$$3")"}}' >wrapfunc_offsets.h

wrapfunc: wrapfunc.c wrapfunc_offsets.h
	gcc -g3 -Wall wrapfunc.c -o wrapfunc -fverbose-asm -fms-extensions -Wa,-aghlms=wrapfunc.s -Wl,-relax -Wl,-q -Wl,-M -Wl,--cref -Wl,-Map=wrapfunc.map


DisplayTerminalSettings.o: DisplayTerminalSettings.c DisplayTerminalSettings.h
	gcc -c DisplayTerminalSettings.c -o DisplayTerminalSettings.o



chipper.o: libchipper.c libchipper.h
	libtool --mode=compile gcc libchipper.c -c -o chipper.o -fms-extensions -D USE_INDIRECTS=$(USE_INDIRECTS) $(CFLAGS) $(ASFLAGS_LIB) $(LDFLAGS_LIB)
#	-Wa,-aghlms=chipper.s
#	gcc libchipper.c -c -o chipper.o -fms-extensions $(ASFLAGS_LIB) $(LDFLAGS_LIB) -D BUILD_SHARED=0 $(CFLAGS) -Wl,-N -Wl,-relax -Wl,-q -Wl,-Bsymbolic-functions -Wa,-aghlms=chipper.s -rdynamic -z nocombreloc -z nocopyreloc -fPIC -r



mulch: mulch.c chipper.o DisplayTerminalSettings.o
	libtool --mode=link gcc mulch.c chipper.o DisplayTerminalSettings.o -o mulch $(CFLAGS) $(ASFLAGS) $(LDFLAGS)
#	gcc mulch.c chipper.o -o mulch $(CFLAGS) $(ASFLAGS) $(LDFLAGS) -Wl,-Bsymbolic-functions -Wl,-relax -Wl,-q -rdynamic -z nocombreloc -z nocopyreloc -fPIC



