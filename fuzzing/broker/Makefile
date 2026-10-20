R=../..
include ${R}/fuzzing/config.mk

.PHONY: all clean

FUZZERS:= \
	broker_fuzz_acl_file \
	broker_fuzz_password_file \
	broker_fuzz_proxy_v1 \
	broker_fuzz_proxy_v2 \
	broker_fuzz_psk_file \
	broker_fuzz_queue_msg \
	broker_fuzz_read_handle \
	broker_fuzz_test_config \
	broker_fuzz_property_read_all \
	broker_fuzz_subscribe \
	broker_fuzz_proxy_v1_decode \
	broker_fuzz_ws_prepare_packet \
	broker_fuzz_bridge_remap_topic_in \
	broker_fuzz_will_set \
	broker_fuzz_properties_to_json

LOCAL_CPPFLAGS+=-I${R}/include/ -I${R}/src -I${R}/lib -I${R} -I${R}/common -I${R}/deps \
	-DWITH_BRIDGE -DWITH_BROKER -DWITH_CONTROL -DWITH_EPOLL \
	-DWITH_MEMORY_TRACKING -DWITH_PERSISTENCE -DWITH_SOCKS -DWITH_SYSTEMD \
	-DWITH_SYS_TREE -DWITH_TLS -DWITH_TLS_PSK -DWITH_UNIX_SOCKETS -DWITH_WEBSOCKETS=WS_IS_BUILTIN
LOCAL_CXXFLAGS+=-g -Wall -Werror -pthread
LOCAL_CFLAGS+=-g -Wall -Werror -pthread
LOCAL_LDFLAGS+=
LOCAL_LIBADD+=$(LIB_FUZZING_ENGINE) -lssl -lcrypto -lcjson -lm ${R}/libcommon/libmosquitto_common.a -Wl,-Bdynamic -Wl,-Bstatic -largon2 -Wl,-Bdynamic
BROKER_A=${R}/src/mosquitto_broker.a

PACKET_FUZZERS:= \
	broker_fuzz_handle_auth \
	broker_fuzz_handle_connect \
	broker_fuzz_handle_publish \
	broker_fuzz_handle_subscribe \
	broker_fuzz_handle_unsubscribe

all: $(FUZZERS) $(PACKET_FUZZERS)

${PACKET_FUZZERS} : %: %.cpp fuzz_packet_read_base.o ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< fuzz_packet_read_base.o  $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@

fuzz_packet_read_base.o : fuzz_packet_read_base.c
	$(CC) $(LOCAL_CFLAGS) $(LOCAL_CPPFLAGS) -c -o $@ $<

broker_fuzz_acl_file : broker_fuzz_acl_file.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_acl_file_seed_corpus.zip ${OUT}/$@_seed_corpus.zip
	cp ${R}/fuzzing/corpora/broker_acl_file.dict ${OUT}/$@.dict

broker_fuzz_password_file : broker_fuzz_password_file.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_password_file_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

broker_fuzz_proxy_v1 : broker_fuzz_proxy_v1.cpp ${R}/src/proxy_v1.o
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< ${R}/src/proxy_v1.o $(LOCAL_LIBADD)
	cp ${R}/fuzzing/corpora/broker_fuzz_proxy_v1_seed_corpus.zip ${OUT}/$@_seed_corpus.zip
	install $@ ${OUT}/$@

broker_fuzz_proxy_v2 : broker_fuzz_proxy_v2.cpp ${R}/src/proxy_v2.o
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< ${R}/src/proxy_v2.o $(LOCAL_LIBADD)
	cp ${R}/fuzzing/corpora/broker_fuzz_proxy_v2_seed_corpus.zip ${OUT}/$@_seed_corpus.zip
	install $@ ${OUT}/$@

broker_fuzz_psk_file : broker_fuzz_psk_file.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_psk_file_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

broker_fuzz_queue_msg : broker_fuzz_queue_msg.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_queue_msg_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

broker_fuzz_read_handle : broker_fuzz_read_handle.cpp fuzz_packet_read_base.o ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_packet_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

broker_fuzz_test_config : broker_fuzz_test_config.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_fuzz_test_config_seed_corpus.zip ${OUT}/$@_seed_corpus.zip
	cp ${R}/fuzzing/corpora/broker_conf.dict ${OUT}/$@.dict

# Top 10 selected harnesses for upstream submission

# MQTT v5 property parsing - tests complex property validation logic
broker_fuzz_property_read_all : broker_fuzz_property_read_all.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/$@_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

# MQTT SUBSCRIBE packet handler - tests subscription tree management
broker_fuzz_subscribe : broker_fuzz_subscribe.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/$@_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

# PROXY protocol v1 decoder - tests network protocol parsing
broker_fuzz_proxy_v1_decode : broker_fuzz_proxy_v1_decode.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/$@_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

# WebSocket packet preparation - tests WebSocket frame building
broker_fuzz_ws_prepare_packet : broker_fuzz_ws_prepare_packet.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/$@_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

# Bridge topic remapping - tests bridge configuration and topic rewriting
broker_fuzz_bridge_remap_topic_in : broker_fuzz_bridge_remap_topic_in.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/$@_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

# MQTT Will message configuration - tests QoS feature and payload validation
broker_fuzz_will_set : broker_fuzz_will_set.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/$@_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

# Property to JSON conversion - tests property serialization
broker_fuzz_properties_to_json : broker_fuzz_properties_to_json.cpp ${R}/src/mosquitto_broker.a
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $< $(BROKER_A) $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/$@_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

clean:
	rm -f *.o $(FUZZERS) $(PACKET_FUZZERS)
