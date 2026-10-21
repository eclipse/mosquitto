#!/bin/sh

# Derive the version from the latest git tag (e.g. v2.1.2-field-dev3 -> 2.1.2-field-dev3).
# Falls back to this hardcoded default if no tag is reachable (e.g. shallow clone).
DEFAULT_VERSION=2.1.2

TAG=$(git describe --tags --abbrev=0 2>/dev/null)
if [ -n "$TAG" ]; then
    VERSION=${TAG#v}
else
    VERSION=$DEFAULT_VERSION
fi

# The LIBMOSQUITTO_* #defines are integers, so only the leading MAJOR.MINOR.REVISION
# numbers are used for them; any suffix (e.g. -field-dev3) is dropped.
MAJOR=$(echo "$VERSION" | sed -E 's/^([0-9]+)\.([0-9]+)\.([0-9]+).*/\1/')
MINOR=$(echo "$VERSION" | sed -E 's/^([0-9]+)\.([0-9]+)\.([0-9]+).*/\2/')
REVISION=$(echo "$VERSION" | sed -E 's/^([0-9]+)\.([0-9]+)\.([0-9]+).*/\3/')

sed -i "s/^VERSION=.*/VERSION=${VERSION}/" config.mk

sed -i "s/^#define LIBMOSQUITTO_MAJOR .*/#define LIBMOSQUITTO_MAJOR ${MAJOR}/" include/mosquitto/libmosquitto.h
sed -i "s/^#define LIBMOSQUITTO_MINOR .*/#define LIBMOSQUITTO_MINOR ${MINOR}/" include/mosquitto/libmosquitto.h
sed -i "s/^#define LIBMOSQUITTO_REVISION .*/#define LIBMOSQUITTO_REVISION ${REVISION}/" include/mosquitto/libmosquitto.h

sed -i "s/^set (VERSION .*)/set (VERSION ${VERSION})/" CMakeLists.txt

sed -i "s/^!define VERSION .*/!define VERSION ${VERSION}/" installer/*.nsi

sed -i "s/^version: .*/version: ${VERSION}/" snap/snapcraft.yaml

sed -i "s/\"version-string\": \".*\",/\"version-string\": \"${VERSION}\",/" vcpkg.json
