#include <stdlib.h>
#define TCACHE_COUNT 7
int main()
{
    char buf[2];
    char *lst[TCACHE_COUNT] = {0};
    //smallbins
    for(int i=0;i<TCACHE_COUNT;i++)
        lst[i] = malloc(2*sizeof(size_t));
    char *ptr1 = malloc(2*sizeof(size_t));
    malloc(2*sizeof(size_t));
    char *ptr2 = malloc(2*sizeof(size_t));
    malloc(2*sizeof(size_t));
    char *ptr3 = malloc(2*sizeof(size_t));
    malloc(2*sizeof(size_t));
    for(int i=0;i<TCACHE_COUNT;i++)
        free(lst[i]);
    free(ptr1);
    free(ptr2);
    free(ptr3);

    //largebins
    ptr1 = malloc(0x82*sizeof(size_t));
    malloc(0x80*sizeof(size_t));
    ptr2 = malloc(0x84*sizeof(size_t));
    malloc(0x80*sizeof(size_t));
    ptr3 = malloc(0x86*sizeof(size_t));
    malloc(0x80*sizeof(size_t));
    char *ptr4 = malloc(0x88*sizeof(size_t));
    malloc(0x80*sizeof(size_t));
    free(ptr1);
    free(ptr2);
    free(ptr3);
    free(ptr4);


    
    malloc(0x1000); //malloc_consolidate
    read(0, buf, 1);
    return 0;
}