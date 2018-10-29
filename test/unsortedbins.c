#include <stdlib.h>
#define TCACHE_COUNT 7
int main()
{
    char buf[2];
    char *lst[TCACHE_COUNT+4] = {0};
    for(int i=0;i<TCACHE_COUNT+4;i++)
        lst[i] = malloc(20*sizeof(size_t));
    for(int i=0;i<TCACHE_COUNT;i++)
        free(lst[i]);

    free(lst[TCACHE_COUNT]);
    free(lst[TCACHE_COUNT+2]);
    read(0, buf, 1);
}