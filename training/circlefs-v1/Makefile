CFLAGS := -std=gnu99

circlefs : circlefs.o
	gcc $(CFLAGS) -g -o circlefs circlefs.o `pkg-config fuse --libs` -lm

circlefs.o : circlefs.c
	gcc $(CFLAGS) -g -Wall `pkg-config fuse --cflags` -c circlefs.c

clean:
	rm -f circlefs *.o

