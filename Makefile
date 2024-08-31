CC = gcc
CFLAGS = -Wall -Wextra
OPENSSL_INC = -I/usr/local/opt/openssl/include
OPENSSL_LIB = -L/usr/local/opt/openssl/lib
LIBS = -lssl -lcrypto

EXECUTABLES = breaker builder

all: $(EXECUTABLES)

breaker: breaker.c
	$(CC) $(CFLAGS) $(OPENSSL_INC) -o $@ $< $(OPENSSL_LIB) $(LIBS)

builder: builder.c
	$(CC) $(CFLAGS) $(OPENSSL_INC) -o $@ $< $(OPENSSL_LIB) $(LIBS)

clean:
	rm -f $(EXECUTABLES)

.PHONY: all clean
