CC=cc
CFLAGS=-g -I/usr/include -fdiagnostics-color=always
LDFLAGS=-lnfc -lssl -lcrypto


all: doorlock certcheck
 
doorlock: doorlock.o
	$(CC) doorlock.o $(LDFLAGS) -o doorlock

certcheck: certcheck.o
	$(CC) certcheck.o $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@
clean:
	rm -rf *.o doorlock certcheck
