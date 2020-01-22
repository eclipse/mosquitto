#!/bin/bash

if [ "$TRAVIS_OS_NAME" == "osx" ]; then
	cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl .
elif [ "$TRAVIS_OS_NAME" == "linux" ]; then
	cmake .
fi
