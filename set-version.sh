#!/bin/sh

MAJOR=1
MINOR=4
REVISION=14

sed -i "s/^VERSION=.*/VERSION=${MAJOR}.${MINOR}.${REVISION}/" config.mk

sed -i "s/^#define LIBMOSQUITTO_MAJOR .*/#define LIBMOSQUITTO_MAJOR ${MAJOR}/" lib/mosquitto.h
sed -i "s/^#define LIBMOSQUITTO_MINOR .*/#define LIBMOSQUITTO_MINOR ${MINOR}/" lib/mosquitto.h
sed -i "s/^#define LIBMOSQUITTO_REVISION .*/#define LIBMOSQUITTO_REVISION ${REVISION}/" lib/mosquitto.h

sed -i "s/^set (VERSION .*)/set (VERSION ${MAJOR}.${MINOR}.${REVISION})/" CMakeLists.txt

sed -i "s/^!define VERSION .*/!define VERSION ${MAJOR}.${MINOR}.${REVISION}/" installer/*.nsi

