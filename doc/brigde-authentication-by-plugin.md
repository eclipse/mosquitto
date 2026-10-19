---
title: 'Mosquitto: using a plugin to authenticate a bridge'
tags:
  - Bridge
  - MQTT
  - Authentication
authors:
  - name: Thorsten Wendt
date: 22 December 2025
---

# Introduction

This patch introduces a new way to provide credentials for bridge
authentication.

Currently the only way to provide authentication credentials was to
set __remote\_username__ and __remote\_password__ in the configuration
file. There was no other way to provide these credentials.

But for example on some platforms these credentials are stored in
a TPM. There is no direct way to pull these credentials from TPM and
use it for bridge authentication.

With this patch these credentials can be provided by a **plugin** that
yields _username_/_password_ on bridge setup and will be used for
broker authentication. Customers can provide this **plugin**
without publishing their source code.

# Plugin interface

The plugin have to register for event **MOSQ_EVT_LOAD_BRIDGE_CRED**.

The callback then will be called before the bride is going to send credentials
to the configured broker. The plugin can set the entries for username and password in the
structure **mosquitto_evt_load_bridge_cred** delivered with the parameter _event\_data_.

The callback can return one of the following value

 * MOSQ_ERR_SUCCESS - Plugin provided username and password
 * MOSQ_ERR_PLUGIN_DEFER - Plugin is not able to provide username/password
 * MOSQ_ERR_AUTH_DENIED - Authentication is denied at all
 * MOSQ_ERR_NOT_FOUND - There will be no username/password at all
 * MOSQ_ERR_NOMEM - Out of memory

# Bridge's behavior

For every bridge the callback(s) of configured auth bridge plugins will be called.

**MOSQ_ERR_SUCCESS:** Username/password is set by the plugin will be used to send it to the broker.

**MOSQ_ERR_PLUGIN_DEFER:** Will call the next plugin if configured otherwise existing remote_username/remote_password will be used to send it to the broker.

**MOSQ_ERR_AUTH_DENIED:** No other plugin will be called and even existing remote_username/remote_password will be ignored. No username/password will be send to the broker.

**MOSQ_ERR_NOT_FOUND:** No further bridge auth plugin will be called even when configured, instead configured remote_username/remote_password will be used to send it to the broker.

**MOSQ_ERR_NOMEM:** Any action to handle bridge configuration will be aborted immediately.

# Examples

Examples can be found in

  - plugins/examples/auth-by-bridge/mosquitto_auth_by_bridge.c
  - test/broker/c/bridge_auth_v1.c
  - test/broker/c/bridge_auth_v2.c

# What's changed inside

The whole algorithm is hooked in function _bridge\_\_new_ in file _bridge.c_.
To implement this new feature the following new constants and a new structure was introduced.

**MOSQ_ERR_AUTH_DENIED** in _enum mosq\_err\_t_.

**MOSQ_EVT_LOAD_BRIDGE_CRED** in _mosquitto\_plugin\_event_ for registering on this new event.

**load_bridge_cred** in structure _plugin\_\_callbacks_ to store auth bridge plugin callbacks.
