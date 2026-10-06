#!/usr/bin/env bash

find -name '*.c' -exec uncrustify -c .uncrustify.cfg --no-backup {} \;
find -name '*.cpp' -exec uncrustify -c .uncrustify.cfg --no-backup {} \;
find -name '*.h' -exec uncrustify -c .uncrustify.cfg --no-backup {} \;

git checkout deps/picohttpparser/picohttpparser.h
git checkout deps/picohttpparser/picohttpparser.c
git checkout deps/utlist.h
git checkout deps/uthash.h
rm -f deps/uthash.h.uncrustify
