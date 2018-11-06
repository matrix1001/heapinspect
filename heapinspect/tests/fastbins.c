#include <stdlib.h>
#define TCACHE_COUNT 7
int main()
{
    char buf[2];
    char *lst[TCACHE_COUNT+3] = {0};
    //fasbins[0]
    for(int i=0;i<TCACHE_COUNT+3;i++)
        lst[i] = malloc(0);
    malloc(2*sizeof(size_t));
    for(int i=0;i<TCACHE_COUNT+3;i++)
        free(lst[i]);
    //fasbins[1]
    for(int i=0;i<TCACHE_COUNT+3;i++)
        lst[i] = malloc(4*sizeof(size_t));
    malloc(4*sizeof(size_t));
    for(int i=0;i<TCACHE_COUNT+3;i++)
        free(lst[i]);
    //fasbins[2]
    for(int i=0;i<TCACHE_COUNT+3;i++)
        lst[i] = malloc(6*sizeof(size_t));
    malloc(6*sizeof(size_t));
    for(int i=0;i<TCACHE_COUNT+3;i++)
        free(lst[i]);
    
    read(0, buf, 1);
    return 0;
}