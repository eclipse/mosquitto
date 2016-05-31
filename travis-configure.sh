#!/bin/bash

if [ "$TRAVIS_OS_NAME" == "osx" -o -n "$LINUX_CMAKE" ]; then
	cmake .
fi
