#!/bin/bash

case ${OSTYPE} in
linux*)
	APT_BIN=$(command -v apt)
	[ -z $APT_BIN ] && APT_BIN=$(command -v apt-get)

	[ -z $APT_BIN ] && {
		echo "Error: failed to find command: 'apt' or 'apt-get'"
		return 1
	}

	sudo ${APT_BIN} update -qq
	sudo ${APT_BIN} install -y debhelper libc-ares-dev libssl-dev libwrap0-dev python-all python3-all uthash-dev uuid-dev libuuid1 xsltproc docbook-xsl
	;;
darwin*)
	brew update
	brew install c-ares openssl libwebsockets
	;;
*)
	echo "Error: unsupported platform"
	;;
esac
