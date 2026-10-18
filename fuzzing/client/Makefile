R=../..
include ${R}/fuzzing/config.mk

.PHONY: all clean

PACKET_FUZZERS:= \
	client_fuzz_read_handle

# IMPORTANT: these -D flags must exactly match the ones used to compile
# lib/libmosquitto.a (see config.mk with WITH_FUZZING=yes). A mismatch changes
# the layout of `struct mosquitto` between this harness and the library and
# leads to memory corruption. In particular WITH_WEBSOCKETS=WS_IS_BUILTIN adds
# fields to the struct, and WITH_BROKER must NOT be defined for the client lib.
LOCAL_CPPFLAGS+=-I${R}/include/ -I${R}/lib -I${R} -I${R}/common \
	-I${R}/deps -I${R}/deps/picohttpparser \
	-DWITH_THREADING -DWITH_TLS -DWITH_TLS_PSK -DWITH_SOCKS \
	-DWITH_UNIX_SOCKETS -DWITH_WEBSOCKETS=WS_IS_BUILTIN -DWITH_FUZZING
LOCAL_CXXFLAGS+=-g -Wall -Werror -pthread
LOCAL_CFLAGS+=-g -Wall -Werror -pthread
LOCAL_LDFLAGS+=
LOCAL_LIBADD+=$(LIB_FUZZING_ENGINE) -lssl -lcrypto -lcjson -lm \
	${R}/libcommon/libmosquitto_common.a \
	-Wl,-Bdynamic -Wl,-Bstatic -largon2 -Wl,-Bdynamic
LIBMOSQ_A=${R}/lib/libmosquitto.a

all: $(PACKET_FUZZERS)

${PACKET_FUZZERS} : %: %.c ${R}/lib/libmosquitto.a
	$(CC) $(LOCAL_CFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(LIBMOSQ_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/client_packet_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

clean:
	rm -f *.o $(PACKET_FUZZERS)
