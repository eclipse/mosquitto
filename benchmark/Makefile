.PHONY: all test 01 02 03 04 08 09 clean reallyclean

CFLAGS=-I../lib -Werror
LIBS=../lib/libmosquitto.so.1
CC=g++

all : mqtt_bench_pub  mqtt_bench_sub

mqtt_bench_pub: MyTimer.cpp MyEpoll.cpp mqtt_bench_pub.cpp 
	g++ -ggdb --std=c++11 ../lib/libmosquitto.so.1 mqtt_bench_pub.cpp MyEpoll.cpp MyTimer.cpp -o $@ -I../lib -Werror ../lib/libmosquitto.so.1 -lpthread -lcrypto

mqtt_bench_sub : MyTimer.cpp MyEpoll.cpp mqtt_bench_sub.cpp 
	g++ -ggdb --std=c++11 ../lib/libmosquitto.so.1 mqtt_bench_sub.cpp MyEpoll.cpp MyTimer.cpp -o $@ -I../lib -Werror ../lib/libmosquitto.so.1 -lpthread -lcrypto

tar: libmosquitto.so.1 mqtt_bench_pub mqtt_bench_sub source.sh ca.crt
	tar czf mqtt_benchmark1.1.tar.gz libmosquitto.so.1 mqtt_bench_pub mqtt_bench_sub source.sh ca.crt

clean :
	rm -f *.o mqtt_bench_pub mqtt_bench_sub
