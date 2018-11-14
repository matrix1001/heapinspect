#include <stdlib.h>
int main()
{
    char buf[20];
    read(0, buf, 1);
    char *p1 = malloc(0x20);
    char *p2 = malloc(0x30);
    char *p3 = malloc(0x40);
    char *p4 = malloc(0x200);
    char *p5 = malloc(0x20);
    read(0, buf, 1);
    free(p1);
    free(p2);
    char *p6 = malloc(0x100);
    read(0, buf, 1);
    free(p4);
    malloc(0x140);
    read(0, buf, 1);
}