R=../..
.PHONY: all clean

FUZZERS:= \
	broker_fuzz_initial_packet \
	broker_fuzz_second_packet \
	broker_fuzz_test_config

LOCAL_CPPFLAGS:=$(CPPFLAGS) -I${R}/include/
LOCAL_CXXFLAGS:=$(CXXFLAGS) -g -Wall -Werror -pthread
LOCAL_LDFLAGS:=$(LDFLAGS)
LOCAL_LIBADD:=$(LIBADD) $(LIB_FUZZING_ENGINE) ${R}/src/mosquitto_broker.a -lssl -lcrypto -lcjson

all: $(FUZZERS)

broker_fuzz_initial_packet : broker_fuzz_initial_packet.cpp broker_fuzz.cpp
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_packet_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

broker_fuzz_second_packet : broker_fuzz_second_packet.cpp broker_fuzz.cpp
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_packet_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

broker_fuzz_test_config : broker_fuzz_test_config.cpp
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/broker_fuzz_test_config_seed_corpus.zip ${OUT}/$@_seed_corpus.zip
	cp ${R}/fuzzing/corpora/broker_conf.dict ${OUT}/$@.dict

clean:
	rm -f *.o $(FUZZERS)
