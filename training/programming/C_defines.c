#include <stdio.h>

#define FOO 5
#define BAR (FOO + 1)
#define BAZ (BAR * 2)

int main(int argc, char *argv[]) {
        printf("FOO is %d\n", FOO);
        printf("BAR is %d\n", BAR);
        printf("BAZ is %d\n", BAZ);
}

/*
$ gcc zz.c -o zz
$ ./zz
FOO is 5
BAR is 6
BAZ is 12
*/


################################################


