#!/bin/bash

if [ "$TRAVIS_OS_NAME" == "osx" ]; then
	brew update
	brew install c-ares openssl libwebsockets
fi

sudo pip install paho-mqtt
