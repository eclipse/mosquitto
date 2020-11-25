Mosquitto for Windows
=====================

Mosquitto for Windows comes in 32-bit and 64-bit flavours.

In both cases, the dependencies are not provided in this installer and must be
installed separately in the case that they are not already available.


Capabilities
------------

Some versions of Windows have limitations on the number of concurrent
connections, set at approximately 2048 connections depending on the version of
Windows you are using.


Websockets
----------

The broker executables provided in the installers have Websockets support
through a statically compiled version of libwebsockets and is being distributed
under the Static Linking Exception (Section 2) of the License. As a result, the
content is not subject to the LGPL 2.1.

Please note that on Windows, libwebsockets limits connections to a maximum of 64 clients.

Library Thread Support
----------------------

libmosquitto on Windows is currently compiled without thread support, so
neither of mosquitto_loop_start() nor "mosquitto_pub -l" are available.

A better solution that the old pthreads-win32 is being looked into, so support
will return in the future. If you need thread support, the code still supports
it just fine. Support has been dropped to simplify installation.

Dependencies
------------

* OpenSSL
    Link: http://slproweb.com/products/Win32OpenSSL.html
    Install "Win32 OpenSSL 1.1.0* Light" or "Win64 OpenSSL 1.1.0* Light"
    Required DLLs: libssl-1_1.dll, libcrypto-1_1.dll or libssl-1_1-x64.dll, libcrypto-1_1-x64.dll

Please ensure that the required DLLs are on the system path, or are in the same directory as
the mosquitto executable - usually C:\Program Files (x86)\mosquitto or C:\Program Files\mosquitto.

Windows Service
---------------

If you wish, mosquitto can be installed as a Windows service so you can
start/stop it from the control panel as well as running it as a normal
executable.

When running as a service, the configuration file used is mosquitto.conf in the
directory that you installed to.

If you want to install/uninstall mosquitto as a Windows service run from the
command line as follows:

C:\Program Files\mosquitto\mosquitto install
C:\Program Files\mosquitto\mosquitto uninstall

Logging
-------

If you use `log_dest file ...` in your configuration, the log file will be
created with security permissions for the current user only. If running as a
service, this means the SYSTEM user. You will only be able to view the log file
if you add permissions for yourself or whatever user you wish to view the logs.
