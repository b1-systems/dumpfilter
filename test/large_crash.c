#include <stdlib.h>
#include <string.h>

#define BLOCK 1024*1024
#define NUMBLOCKS 100

int main(int argc, char *argv[]) {
    int i = 0, randfp;
    char buffer[BLOCK];
    char *x;

    randfp = open("/dev/urandom", "r");

    for(;i<NUMBLOCKS; i++) {
        x = malloc(BLOCK);
        read(randfp, &buffer, BLOCK);
        memcpy(x, &buffer, BLOCK);
    }
    x = "crashme :-)";
    free(x);
}
