Mosquitto for Windows
=====================

Mosquitto for Windows comes in two flavours, win32 or Cygwin. The win32 version is only
supported on Windows Vista or later.

In all cases, the dependencies are not provided in this installer and must be installed
separately in the case that they are not already available.


Capabilities
------------

Some versions of Windows have limitations on the number of concurrent
connections. Non-server versions have been reported to be limited to
approximately 1024 connections.


Websockets
----------

The broker executables provided in the installers do not have Websockets support enabled.
If you wish to have a version of the broker with Websockets support, you will need to compile
libwebsockets version v1.7 onwards because no Windows binaries are provided.

Please note that on Windows, libwebsockets limits connections to a maximum of 64 clients.


Dependencies - win32
--------------------

* OpenSSL
    Link: http://slproweb.com/products/Win32OpenSSL.html
    Install "Win32 OpenSSL <version>"
    Required DLLs: libeay32.dll ssleay32.dll
* pthreads
    Link: ftp://sourceware.org/pub/pthreads-win32
    Install "pthreads-w32-<version>-release.zip
    Required DLLs: pthreadVC2.dll

Please ensure that the required DLLs are on the system path, or are in the same directory as
the mosquitto executable.


Dependencies - Cygwin
---------------------

* OpenSSL
    Link: http://slproweb.com/products/Win32OpenSSL.html
    Install "Win32 OpenSSL <version>"
* pthreads
    Link: ftp://sourceware.org/pub/pthreads-win32
    Install "pthreads-w32-<version>-release.zip
* Cygwin
    Link: https://www.cygwin.com/setup-x86.exe
    Required packages: libgcc1, openssl, zlib0


Windows Service
---------------

If all dependencies are installed prior to the installer being run, the broker can be
installed as a Windows service.

You can start/stop it from
 the control panel as well as running it as a normal
executable.

When running as a service, the configuration in mosquitto.conf in the
installation directory is used so modify this to your needs.
