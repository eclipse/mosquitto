The following packages can be used to add features to mosquitto. See below for
platform specific package lists.

* cJSON - required
* c-ares (libc-ares-dev on Debian based systems) - optional, enable with
  `WITH_SRV=yes`
* libedit - for mosquitto_ctrl interactive shell - optional, disable with
  `WITH_EDITLINE=no`
* libmicrohttpd - for broker http api support - optional, disable with
  `WITH_HTTP_API=no`
* openssl (libssl-dev on Debian based systems) - optional, disable with
  `WITH_TLS=no`
* pthreads - for client library thread support. This is required to support the
  `mosquitto_loop_start()` and `mosquitto_loop_stop()` functions. If compiled
  without pthread support, the library isn't guaranteed to be thread safe.
* sqlite3 - for persistence support in the broker - optional, disable with
  `WITH_SQLITE=no`
* uthash / utlist - bundled versions of these headers are provided, disable
  their use with `WITH_BUNDLED_DEPS=no`
* xsltproc (xsltproc and docbook-xsl on Debian based systems) - only needed
  when building from git sources - disable with `WITH_DOCS=no`

For testing, the following packages are required:
* cunit
* googletest / gmock
* microsocks
* python


To compile you may either use CMake, or on Linux look in the file `config.mk`
for compile options and use plain `make`.

Up to version 2.1, the recommendation was to use CMake for Windows and Mac, and
to use make everywhere else. The recommendation now is to use cmake in all
cases, and that the plain makefiles will be removed in version 3.0.

If you have any questions, problems or suggestions (particularly related to
installing on a more unusual device) then please get in touch using the details
in README.md.

## Platform specific dependencies

### Alpine Linux

apk add cjson-dev cmake cunit-dev docbook-xsl g++ gcc gtest-dev libmicrohttpd-dev \
    libxslt make musl-dev openssl-dev sqlite-dev

### Fedora Linux

dnf install CUnit-devel cjson-devel cmake docbook-style-xsl gcc gcc-g++ gmock-devel \
    gtest-devel libmicrohttpd-devel libxslt openssl-devel openssl-devel-engine sqlite-devel

### FreeBSD

pkg install cunit gmake googletest libcjson libmicrohttpd libxslt python3 sqlite3 uthash

### Ubuntu Linux

apt install cmake docbook-xsl gcc g++ libcjson-dev libcunit1-dev libeditreadline-dev \
    libgmock-dev libgtest-dev libmicrohttpd-dev libsqlite3-dev libssl-dev xsltproc
