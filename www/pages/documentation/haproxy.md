<!--
.. title: Using Mosquitto with HAProxy
.. slug: haproxy
.. date: 2024-04-14 22:32:58 UTC
.. tags:
.. category:
.. link:
.. description:
.. type: text
-->


[TOC]

## Introduction

Using Mosquitto as an entirely standalone broker works very well, but sometimes
you may wish to place it behind a load balancer / proxy such as [HAProxy]. This
provides certain advantages such as carrying out TLS termination in the proxy
to reduce load on the broker. It does have one disadvantage which is that only
the proxy IP address is found in the broker logs - the client IP addresses are
not seen. Since Mosquitto 2.1, this can be fixed using the PROXY protocol v2
support, which can be enabled using the `enable_proxy_protocol_v2` option. This
is the recommended mode when using HAProxy.

This document describes some different ways you can combine Mosquitto and
HAProxy. It is not a complete guide to HAProxy.

**Important:** Enabling PROXY protocol support requires that the broker itself
is not directly accessible on its network port. All communication must go
through the broker. If a client is able to connect to the broker directly, it
is trivial to spoof connection information and this is especially important
when using client certificates for mutual TLS on HAProxy. In that case, the
contents of the PROXY header can directly indicate whether a client is allowed
to connect so it must be protected.

It may be desirable to use a firewall to restrict access to the broker port.

## General setup

All examples presented will be of the `haproxy.cfg` file, typically located at
`/etc/haproxy/haproxy.cfg` on a native Linux installation.

The first part of the config file contains the `global` and `defaults` sections
which are going to be common to all of the examples and not repeated.

### Global section

This is a fairly standard global section, presented without comment.

```
global
        log /dev/log    local0
        log /dev/log    local1 notice
        user haproxy
        group haproxy
        daemon

        # Default SSL material locations
        ca-base /etc/ssl/certs
        crt-base /etc/ssl/private

        # See: https://ssl-config.mozilla.org/#server=haproxy&server-version=2.0.3&config=intermediate
        ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
        ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
        ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
```

### Defaults section

```
defaults
        mode    tcp
        timeout connect 5000
        timeout client  60000
        timeout server  60000
```

* `mode tcp` - set TCP mode rather than HTTP mode by default. MQTT is not HTTP.
* `timeout connect 5000` - the timeout allowed for a client to connect, in
  milliseconds.
* `timeout client 60000` - if a client does not communicate in this interval,
  the connection will be closed by HAProxy.
* `timeout server 60000` - if the broker does not communicate in this interval,
  the connection will be closed by HAProxy.

The client and server timeout intervals should be chosen based on the intervals
you expect to have communication occurring in your clients. If your
communication is typically very sparse, the timeout should be chosen based on
the keepalive interval you are using, otherwise the quiet clients will be
disconnected before they have chance to send a keepalive request.

## Direct pass through, without PROXY protocol

The most basic approach is to pass connections directly through HAProxy to
Mosquitto without being modified. This means that if an unencrypted MQTT
connection is made, it will pass throughas an unencrypted connection, and if an
encrypted MQTT connection is made it will pass through as an encrypted MQTT
connection. Likewise, websockets connections are passed through unaffected.

Create a frontend, which is where HAProxy will listen for connections, and a
backend which is where the broker that HAProxy will connect to is defined.

```
frontend mqtt_frontend
         bind *:1883
         default_backend mqtt_backend

backend mqtt_backend
        server server1 127.0.0.1:1884 check on-marked-down shutdown-sessions
```

In this case, HAProxy is listening on all interfaces on port 1883 and will
attempt to connect to the broker on address 127.0.0.1 on port 1884. In other
words, HAProxy and Mosquitto are running on the same instance. This is not
required.

The broker configuration could be with an encrypted or unencrypted listener:

Unencrypted:
```
listener 1884
# Further listener settings
```

Encrypted:
```
listener 1884
certfile <path/to/server.crt>
keyfile <path/to/server.key>
# Further listener settings
```

## TLS termination with server certificate only, without PROXY protocol

Place your server certificate and private key in `/etc/haproxy/certs/`.

```
frontend mqtts_frontend
         bind 0.0.0.0:8883 ssl crt /etc/haproxy/certs/

backend mqtt_backend
        server server1 127.0.0.1:1883 check on-marked-down shutdown-sessions
```

The broker configuration should declare an unencrypted listener:

```
listener 1883
# Further listener settings
```

## TLS termination with mutual TLS - client and server certificates, without PROXY protocol

In addition to the server certificate, you must also provide the CA certificate
that will sign the client certificates, ask for verification of the client
certificate and make the certificate required.

```
frontend mqtts_frontend
         bind *:8883 ssl crt /etc/haproxy/certs/ verify required ca-file /etc/haproxy/client-ca.crt
         default_backend mqtt_backend

backend mqtt_backend
        server server1 127.0.0.1:1883 check on-marked-down shutdown-sessions
```

The broker configuration should declare an unencrypted listener:

```
listener 1883
# Further listener settings
```

## Direct pass through, with PROXY protocol

To enable PROXY protocol v2 on HAProxy, add the `send-proxy-v2` option to the backend.
```
frontend mqtt_frontend
         bind *:1883
         default_backend mqtt_backend

backend mqtt_backend
        server server1 127.0.0.1:1884 check on-marked-down shutdown-sessions send-proxy-v2
```

The broker configuration should declare an unencrypted listener and enable
PROXY protocol v2 support. It is not possible to have direct pass through
with encrypted connections on the broker.
```
listener 1883
enable_proxy_protocol_v2 true
# Further listener settings
```


## TLS termination with server certificate only, with PROXY protocol

For TLS connections, use `send-proxy-v2-ssl` instead of `send-proxy-v2`. This
ensures that TLS information is added to the PROXY header.
```
frontend mqtts_frontend
         bind *:8883 ssl crt /etc/haproxy/certs/
         default_backend mqtt_backend

backend mqtt_backend
        server server1 127.0.0.1:1883 check on-marked-down shutdown-sessions send-proxy-v2-ssl
```

On the broker side, use `proxy_protocol_v2_require_tls true` to ensure that
only connections that were made using TLS are accepted on the broker. No other
TLS configuration is required.
```
listener 1883
enable_proxy_protocol_v2 true
proxy_protocol_v2_require_tls true
```

## TLS termination with mutual TLS - client and server certificate, with PROXY protocol

For TLS connections, use `send-proxy-v2-ssl` instead of `send-proxy-v2`. This
ensures that TLS information is added to the PROXY header.

```
frontend mqtts_frontend
         bind *:8883 ssl crt /etc/haproxy/certs/ verify required ca-file /etc/haproxy/client-ca.crt
         default_backend mqtt_backend

backend mqtt_backend
        server server1 127.0.0.1:1883 check on-marked-down shutdown-sessions send-proxy-v2-ssl
```

The broker configuration uses `require_certificate true` to indicate that
the broker should check the PROXY protocol header for the valid certificate
result. No other TLS configuration is required.
```
listener 1883
enable_proxy_protocol_v2 true
proxy_protocol_v2_require_tls true
require_certificate true
```


## TLS termination with mutual TLS - client and server certificate, with username and PROXY protocol

The Mosquitto option `use_identity_as_username true` can be used with the PROXY
protocol support. This requires that the `send-proxy-v2-ssl-cn` option is used
on HAProxy.

It is not possible to use `use_subject_as_username` with the PROXY protocol.

```
frontend mqtts_frontend
         bind *:8883 ssl crt /etc/haproxy/certs/ verify required ca-file /etc/haproxy/client-ca.crt
         default_backend mqtt_backend

backend mqtt_backend
        server server1 127.0.0.1:1883 check on-marked-down shutdown-sessions send-proxy-v2-ssl-cn
```

The broker configuration uses `require_certificate` and
`use_identity_as_username`. No other TLS configuration is required.
```
listener 1883
enable_proxy_protocol_v2 true
proxy_protocol_v2_require_tls true
require_certificate true
use_identity_as_username true
```


[HAProxy]:https://www.haproxy.org/
