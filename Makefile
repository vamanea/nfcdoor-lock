CC=cc
CFLAGS=-g -I/usr/include -c -fdiagnostics-color=always
LDFLAGS=-lnfc -lssl -lcrypto
 
all: doorlock.o doorlock
 
doorlock: doorlock.o
	$(CC) doorlock.o $(LDFLAGS) -o doorlock
 
doorlock.o: doorlock.c
	$(CC) $(CFLAGS) doorlock.c

clean:
	rm -rf *.o doorlock
