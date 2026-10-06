#!/usr/bin/env bash
#
# Copyright (c) 2023 Cedalo GmbH
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Eclipse Public License 2.0
# and Eclipse Distribution License v1.0 which accompany this distribution.
#
# The Eclipse Public License is available at
#   https://www.eclipse.org/legal/epl-2.0/
# and the Eclipse Distribution License is available at
#   http://www.eclipse.org/org/documents/edl-v10.php.
#
# SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
#
# Contributors:
#    Roger Light - initial implementation and documentation.

set -eu

export CC=clang
export CXX=clang++

# Note that sqlite3 is required as a build dep of a plugin which is not
# currently part of fuzz testing. Once it is part of fuzz testing, sqlite will
# need to be built statically.
apt-get update && apt-get install -y \
	cmake \
	libargon2-dev \
	libedit-dev \
	liblzma-dev \
	libmicrohttpd-dev \
	libsqlite3-dev \
	libtool-bin \
	libz-dev \
	make \
	ninja-build \
	pkg-config \
	uthash-dev
git clone https://github.com/ralight/cJSON ${SRC}/cJSON
git clone https://github.com/ralight/mallocfail ${SRC}/mallocfail
git clone https://github.com/ianlancetaylor/libbacktrace ${SRC}/libbacktrace

# If building outside of oss-fuzz, we need LPM
if [ ! -d ${SRC}/LPM ]; then
	git clone https://github.com/google/libprotobuf-mutator ${SRC}/libprotobuf-mutator

	mkdir ${SRC}/LPM \
		&& cd ${SRC}/LPM \
		&& cmake ../libprotobuf-mutator -GNinja \
			-DCMAKE_POSITION_INDEPENDENT_CODE=ON \
			-DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON \
			-DLIB_PROTO_MUTATOR_TESTING=OFF \
			-DLIB_PROTO_MUTATOR_EXAMPLES=OFF \
			-DCMAKE_BUILD_TYPE=Release \
		&& ninja
fi
