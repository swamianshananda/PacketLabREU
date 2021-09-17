CFLAGS= -g -Wall -std=gnu99 -O0 -I../pktlab-libpktlab/include 
LIBS=../pktlab-libpktlab/libpktlab.a
all: sampleStuff httpTrial bottleneck

sampleStuff: sampleStuff.c $(LIBS)
	gcc $(CFLAGS) $^ -o $@

httpTrial: httpTrial.c $(LIBS)
	gcc $(CFLAGS) $^ -o $@
	
bottleneck: bottleneck.c bottleneck.h $(LIBS)
	gcc $(CFLAGS) $^ -o $@

clean:
	rm -f sampleStuff httpTrial bottleneck
