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

export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"
export CFLAGS
export CXXFLAGS
export LDFLAGS

# Build direct broker dependency - cJSON
# Note that other dependencies, i.e. sqlite are not yet built because they are
# only used by plugins and not currently otherwise used.
cd ${SRC}/cJSON
cmake \
	-DBUILD_SHARED_LIBS=OFF \
	-DCMAKE_C_FLAGS=-fPIC \
	-DENABLE_CJSON_TEST=OFF \
	.
make -j $(nproc)
make install

cd ${SRC}/libbacktrace
./configure
make -j $(nproc)
make install

cd ${SRC}/mallocfail
cmake -B build -S .
cmake --build build
cmake --install build

# Build broker and library static libraries
cd ${SRC}/mosquitto
cmake -B build -S . -GNinja \
	-DCMAKE_BUILD_TYPE=Debug \
	-DWITH_CTRL_SHELL=OFF \
	-DWITH_DOCS=OFF \
	-DWITH_FUZZING=ON \
	-DWITH_HTTP_API=OFF
cmake --build build
cmake --install build
