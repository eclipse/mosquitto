R=../..
CFLAGS=-Wall -ggdb -I${R}/lib -I${R}/lib/cpp
LDFLAGS=-L${R}/lib ${R}/lib/cpp/libmosquittopp.so.1 ${R}/lib/libmosquitto.so.1

.PHONY: all clean

all : mqtt_temperature_conversion

mqtt_temperature_conversion : main.o temperature_conversion.o
	${CXX} $^ -o $@ ${LDFLAGS}

main.o : main.cpp
	${CXX} -c $^ -o $@ ${CFLAGS}

temperature_conversion.o : temperature_conversion.cpp
	${CXX} -c $^ -o $@ ${CFLAGS}

clean :
	-rm -f *.o mqtt_temperature_conversion
