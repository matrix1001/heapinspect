CC = gcc 

CFLAGS  = -g


all: fastbins bins unsortedbins fastbins32 bins32 unsortedbins32
    
fastbins: fastbins.c
	$(CC) fastbins.c $(CFLAGS) -o fastbins64 

bins: bins.c
	$(CC) bins.c $(CFLAGS) -o bins64

unsortedbins: unsortedbins.c
	$(CC) unsortedbins.c $(CFLAGS) -o unsortedbins64

fastbins32: fastbins.c
	$(CC) fastbins.c $(CFLAGS) -m32 -o fastbins32

bins32: bins.c
	$(CC) bins.c $(CFLAGS) -m32 -o bins32

unsortedbins32: unsortedbins.c
	$(CC) unsortedbins.c $(CFLAGS) -m32 -o unsortedbins32

clean:
	$(RM) fastbins64 bins64 unsortedbins64 fastbins32 bins32 unsortedbins32
