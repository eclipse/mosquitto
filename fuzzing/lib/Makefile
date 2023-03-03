R=../..
.PHONY: all clean

FUZZERS:= \
	lib_fuzz_pub_topic_check2 \
	lib_fuzz_sub_topic_check2 \
	lib_fuzz_utf8

LOCAL_CPPFLAGS:=$(CPPFLAGS) -I${R}/include/
LOCAL_CXXFLAGS:=$(CXXFLAGS) -g -Wall -Werror -pthread
LOCAL_LDFLAGS:=$(LDFLAGS)
LOCAL_LIBADD:=$(LIBADD) $(LIB_FUZZING_ENGINE) ${R}/lib/libmosquitto.a -lssl -lcrypto

all: $(FUZZERS)

lib_fuzz_pub_topic_check2 : lib_fuzz_pub_topic_check2.cpp
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)
	install $@ ${OUT}/$@

lib_fuzz_sub_topic_check2 : lib_fuzz_sub_topic_check2.cpp
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)
	install $@ ${OUT}/$@

lib_fuzz_utf8 : lib_fuzz_utf8.cpp
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)
	install $@ ${OUT}/$@

clean:
	rm -f *.o $(FUZZERS)
