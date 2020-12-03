The following packages can be used to add features to mosquitto. All of them
are optional.

* openssl
* c-ares (for DNS-SRV support, disabled by default)
* tcp-wrappers (optional, package name libwrap0-dev)
* libwebsockets (optional, disabled by default, version 2.4 and above)
* cJSON (optional but recommended, for dynamic-security plugin support, and
  JSON output from mosquitto_sub/mosquitto_rr)
* On Windows, a pthreads library is required if threading support is to be
  included.

To compile, run "make", but also see the file config.mk for more details on the
various options that can be compiled in.

Where possible use the Makefiles to compile. This is particularly relevant for
the client libraries as symbol information will be included.  Use cmake to
compile on Windows or Mac.

If you have any questions, problems or suggestions (particularly related to
installing on a more unusual device) then please get in touch using the details
in README.md.
