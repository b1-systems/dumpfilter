#include <stdlib.h>
int main(int argc, char *argv[]) {
    int i = 0;
    char *x;
    for(;i<100; i++) {
        x = malloc(1024*1024);
    }
    x = "crashme :-)";
    free(x);
}
