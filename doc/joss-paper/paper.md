---
title: 'Mosquitto: server and client implementation of the MQTT protocol'
tags:
  - Internet of Things
  - MQTT
  - Pubsub
  - Messaging
authors:
  - name: Roger A Light
    orcid: 0000-0001-9218-7797
date: 17 May 2017
bibliography: paper.bib
---

# Summary

Mosquitto provides standards compliant server and client implementations of the
[MQTT](http://mqtt.org/) messaging protocol. MQTT uses a publish/subscribe
model, has low network overhead and can be implemented on low power devices
such microcontrollers that might be used in remote Internet of Things sensors.
As such, Mosquitto is intended for use in all situations where there is a need
for lightweight messaging, particularly on constrained devices with limited
resources.

The Mosquitto project is a member of the [Eclipse Foundation](http://eclipse.org/)

There are three parts to the project.

* The main `mosquitto` server
* The `mosquitto_pub` and `mosquitto_sub` client utilities that are one method of communicating with an MQTT server
* An MQTT client library written in C, with a C++ wrapper

Mosquitto allows research directly related to the MQTT protocol itself, such as
comparing the performance of MQTT and the Constrained Application Protocol
(CoAP) [@Thangavel_2014] or investigating the use of OAuth in MQTT
[@Fremantle_2014].  Mosquitto supports other research activities as a useful
block for building larger systems and has been used to evaluate MQTT for use in
Smart City Services [@Antonic_2015], and in the development of an environmental
monitoring system [@Bellavista_2017]. Mosquitto has also been used to support
research less directly as part of a scheme for remote control of an experiment
[@Schulz_2014].

Outside of academia, Mosquitto is used in other open source projects such as
the [openHAB](http://www.openhab.org/) home automation project and
[OwnTracks](http://owntracks.org/), the personal location tracking project, and
has been integrated into commercial products.

# References

