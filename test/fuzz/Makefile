include ../../config.mk

TARGET=fuzzer

CC=clang
CFLAGS:=$(CFLAGS) -fsanitize=address,fuzzer
LDFLAGS:=$(LDFLAGS) -fsanitize=address,fuzzer
LIBS=../../lib/libmosquitto.a

CFLAGS:=$(CFLAGS) -I../.. -I../../include -I../../lib -I../../src -I../../deps

all:

fuzzer.o: fuzzer.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(TARGET): fuzzer.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

fuzz: $(TARGET)
	./$(TARGET)

clean:
	rm $(TARGET) *.o crash* leak*

.PHONY: fuzz clean

