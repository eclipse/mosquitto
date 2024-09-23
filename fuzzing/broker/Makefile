R=../..
include ${R}/fuzzing/config.mk

.PHONY: all clean

FUZZERS:= \
	broker_fuzz_acl_file \
	broker_fuzz_password_file \
	broker_fuzz_psk_file \
	broker_fuzz_queue_msg \
	broker_fuzz_read_handle \
	broker_fuzz_test_config

LOCAL_CPPFLAGS+=-I${R}/include/ -I${R}/src -I${R}/lib -I${R} -I${R}/common -I${R}/deps \
	-DWITH_BRIDGE -DWITH_BROKER -DWITH_CONTROL -DWITH_EC -DWITH_EPOLL \
	-DWITH_MEMORY_TRACKING -DWITH_PERSISTENCE -DWITH_SOCKS -DWITH_SYSTEMD \
	-DWITH_SYS_TREE -DWITH_TLS -DWITH_TLS_PSK -DWITH_UNIX_SOCKETS -DWITH_WEBSOCKETS=WS_IS_BUILTIN
LOCAL_CXXFLAGS+=-g -Wall -Werror -pthread
LOCAL_LDFLAGS+=
LOCAL_LIBADD+=$(LIB_FUZZING_ENGINE) ${R}/src/mosquitto_broker.a -lssl -lcrypto -lcjson -lm ${R}/libcommon/libmosquitto_common.a -Wl,-Bdynamic -Wl,-Bstatic -largon2 -Wl,-Bdynamic

all: $(FUZZERS)

broker_fuzz_acl_file : broker_fuzz_acl_file.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_acl_file_seed_corpus.zip ${OUT}/$@_seed_corpus.zip
	cp ${R}/fuzzing/corpora/broker_acl_file.dict ${OUT}/$@.dict

broker_fuzz_password_file : broker_fuzz_password_file.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_password_file_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

broker_fuzz_psk_file : broker_fuzz_psk_file.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_psk_file_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

broker_fuzz_queue_msg : broker_fuzz_queue_msg.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_queue_msg_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

broker_fuzz_read_handle : broker_fuzz_read_handle.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_packet_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

broker_fuzz_test_config : broker_fuzz_test_config.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_fuzz_test_config_seed_corpus.zip ${OUT}/$@_seed_corpus.zip
	cp ${R}/fuzzing/corpora/broker_conf.dict ${OUT}/$@.dict

clean:
	rm -f *.o $(FUZZERS)
