CC ?= gcc
GNUTLS_CFLAGS ?= $(shell pkg-config gnutls --cflags)
GNUTLS_LDFLAGS ?= $(shell pkg-config gnutls --libs)
LNICE_CFLAGS ?= $(shell pkg-config nice --cflags)
LNICE_LDFLAGS ?= $(shell pkg-config nice --libs)
DEBUG_CFLAGS ?=

CFLAGS += -O -g3 ${GNUTLS_CFLAGS} ${LNICE_CFLAGS}  ${DEBUG_CFLAGS}

all: ripeer

ripeer: ripeer.o 
	$(CC) -o ripeer ripeer.o -I.   ${CFLAGS} ${GNUTLS_LDFLAGS} ${LNICE_LDFLAGS}

clean:
	rm -f *.o ripeer


%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
