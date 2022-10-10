Mosquitto for Windows
=====================

Mosquitto for Windows comes in 64-bit and 32-bit flavours. All dependencies are
provided in the installer.

Installing
----------

Running the installer will present the normal type of graphical installer. If
you want to install without starting the graphical part of the installer, you
can do so by running it from a cmd prompt with the `/S` switch:

```
mosquitto-2.0.12-install-windows-x64.exe /S
```

You can override the installation directory with the `/D` switch:

```
mosquitto-2.0.12-install-windows-x64.exe /S /D=:\mosquitto
```


Capabilities
------------

Some versions of Windows have limitations on the number of concurrent
connections due to the Windows API being used. In modern versions of Windows,
e.g. Windows 10 or Windows Server 2019, this is approximately 8192 connections.
In earlier versions of Windows, this limit is 2048 connections.


Windows Service
---------------

If you wish, mosquitto can be installed as a Windows service so you can
start/stop it from the control panel as well as running it as a normal
executable.

When running as a service, the configuration file used is mosquitto.conf in the
directory defined by the %MOSQUITTO_DIR% environment variable. This will be set
to the directory that you installed to by default.

If you want to install/uninstall mosquitto as a Windows service run from the
command line as follows:

C:\Program Files\mosquitto\mosquitto install
C:\Program Files\mosquitto\mosquitto uninstall

It is possible to install and run multiple instances of a Mosquitto service, as
of version 2.1. To do this, copy the mosquitto executable to a new *name* and
run the service install as above. The service will load a configuration file
mosquitto.conf from the directory defined by the environment variable
"<executable_name>_DIR". For this reason it is suggested to keep the executable
name consisting of alphanumeric and '_' characters. Any other character will be
replaced with '_'.

For example, if you copy mosquitto.exe to eclipse_mosquitto.exe, you would run
these commands to install/uninstall:

C:\Program Files\mosquitto\eclipse_mosquitto install
C:\Program Files\mosquitto\eclipse_mosquitto uninstall

And the service would try to load the config file at %ECLIPSE_MOSQUITTO_DIR%/mosquitto.conf

The new service will appear in the service list as "Mosquitto Broker (eclipse_mosquitto.exe)".

Logging
-------

If you use `log_dest file ...` in your configuration, the log file will be
created with security permissions for the current user only. If running as a
service, this means the SYSTEM user. You will only be able to view the log file
if you add permissions for yourself or whatever user you wish to view the logs.
