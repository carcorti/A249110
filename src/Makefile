CC = gcc
CPPFLAGS ?=
CFLAGS = -O3 -std=c17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wdouble-promotion -Wformat=2 -Werror -fopenmp
LDFLAGS ?= -fopenmp
LDLIBS ?= -lgmp -lcrypto
SOURCE_SHA := $(shell sha256sum a249110.c | cut -d' ' -f1)
MAKE_SHA := $(shell sha256sum Makefile | cut -d' ' -f1)
BIND = -DA249110_SOURCE_SHA='"$(SOURCE_SHA)"' -DA249110_MAKE_SHA='"$(MAKE_SHA)"'

.PHONY: all clean check
all: a249110

a249110: a249110.c Makefile
	$(CC) $(CPPFLAGS) $(BIND) $(CFLAGS) -o $@ a249110.c $(LDFLAGS) $(LDLIBS)

check: a249110
	python3 -B ../check/verify.py native

clean:
	rm -f a249110
