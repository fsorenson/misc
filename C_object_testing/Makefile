CC=gcc

all: test12
#all: c_obj_1 test7 test8 test9 test10 test11


test6.o: test6.lds test6.c test6.h
	gcc test6.c -T test6.lds -o test6.o -r -fPIC -nostdlib -nodefaultlibs -Wl,--cref 2>&1

c_obj_1: c_obj_1.c test6.o
	gcc -ggdb3 c_obj_1.c -o c_obj_1 -L /var/tmp/c_obj -l:test6.o



#test7.lds: default.lds test7_custom.lds
#	# do something to merge the default and custom


test7: test7.c test7.lds
	gcc test7.c -otest7 -T test7.lds 2>&1

#	gcc test7.c -otest7 -T test7.lds -fPIC -Wl,--verbose 2>&1


#	gcc -ggdb3 c_obj_1.c test6.o -o c_obj_1


libtest8.so: test8_lib.c test8_lib.h
	gcc -T default.ld -T test8_lib.lds test8_lib.c -o libtest8.so -shared -fPIC -rdynamic
#	gcc test8_lib.c -o libtest8.so -shared -fPIC -rdynamic


#	gcc test8_lib.c -o libtest8.so -shared -fPIC -rdynamic -nostdlib -nodefaultlibs
#	gcc test8.c -o test8 -l dl -L `pwd` -ltest8
#

#	gcc test8_lib.c -o libtest8.so -shared -fPIC -rdynamic

test8: test8.c libtest8.so
	gcc test8.c -o test8 -l dl



test9_lib_abs.o: test9_lib_abs.c test9_lib_abs.h
	gcc -g -c test9_lib_abs.c -o test9_lib_abs.o
#	gcc -g test9_lib_abs.c -o test9_lib_abs.o -rdynamic -fPIC -nostdlib -nodefaultlibs

#test9_lib.o: test9_lib.c test9_lib.h test9_lib.lds
#	gcc -g -T test9_lib.lds test9_lib.c -o test9_lib.o -r -fPIC -nostdlib -nodefaultlibs
test9_lib.o: test9_lib.c test9_lib.h test9_lib.lds
	gcc -g -T test9_lib.lds -c test9_lib.c -o test9_lib.o -fpic
#	gcc -g -T test9_lib.lds test9_lib.c -o test9_lib.o -fpic -r -nodefaultlibs -nostdlib


test9: test9.c test9_lib.o test9_lib_abs.o
	gcc -g test9.c test9_lib.o test9_lib_abs.o -o test9

#	gcc -g test9.c -Wl,--push-


ASFILE=asm.out
MAPFILE=map

ASFLAGS=-Wa,-adhlmns=$(ASFILE)
#LDFLAGS=-Wl,-M -Wl,-Map=$(MAPFILE) -Wl,--cref
//LDFLAGS=-Wl,-M -Wl,-Map=$(MAPFILE)
LDFLAGS=-Wl,--cref -Wl,-Map=$(MAPFILE)

#test10: test10.c test10_lib.o
#	gcc -g test10.c test10_lib.o test10_lib_abs.o -o test10
test10_lib.o: test10_lib.c test10_lib.h
	gcc -g test10_lib.c -o test10_lib.o -rdynamic -fpic -shared

test10: test10.c test10_lib.c test10_lib.h test10_lib.o
	gcc -ggdb3 test10.c test10_lib.c -o test10 -ldl
#	gcc -ggdb3 test10.c test10_lib.c -o test10 $(ASFLAGS) $(LDFLAGS)


libtest11.so: test11_lib.c test11_lib.h
	gcc -ggdb3 -shared test11_lib.c -o libtest11.so -rdynamic -fpic

test11: test11.c libtest11.so
	gcc -ggdb3 test11.c -o test11 -ldl



ASFILE=asm.out
MAPFILE=map

ASFLAGS=-Wa,-adhlmns=$(ASFILE)
ASFLAGS_LIB=$(ASFLAGS)-lib
#LDFLAGS=-Wl,-M -Wl,-Map=$(MAPFILE) -Wl,--cref
//LDFLAGS=-Wl,-M -Wl,-Map=$(MAPFILE)
LDFLAGS_LIB=-Wl,--cref -Wl,-Map=$(MAPFILE)-lib
LDFLAGS=-Wl,--cref -Wl,-Map=$(MAPFILE)


libtest12.so: test12_lib.c test12_lib.h
	gcc -ggdb3 -shared test12_lib.c -o libtest12.so -rdynamic -fpic $(ASFLAGS_LIB) $(LDFLAGS_LIB)

test12: test12.c libtest12.so
	gcc -ggdb3 test12.c -o test12 -ldl $(ASFLAGS) $(LDFLAGS)


# gcc -ggdb3 -g -gstabs+ -c -T test12_lib_export.lds test12_lib.c -o test12_lib_export.o -fpic -fpie

###

##


# test
#gcc -g -c -T test9_lib.lds -c test9_lib.c -o test9_lib.o -fpic -fpie
#gcc -g test9.c test9_lib.o test9_lib_abs.o -o test9 -Wl,-T -Wl,test9_merged.lds






