<!--
.. title: test.mosquitto.org SSL cert updated
.. slug: test-mosquitto-org-ssl-cert-updated
.. date: 2020-06-09 12:30:13 UTC+01:00
.. tags: Public-server
.. category:
.. link:
.. description:
.. type: text
-->

The CA certificate and server certificate for the broker running at
[test.mosquitto.org] has been updated to use a stronger key.

This means that if you have downloaded the CA certificate, you will need to do
so again.

Likewise, if you have used the [client certificate generator] then your
certificate will no longer be accepted and you must generate a new one.

[test.mosquitto.org]: https://test.mosquitto.org
[client certificate generator]: https://test.mosquitto.org/ssl/
