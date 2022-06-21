#!/usr/bin/env python3

from pathlib import Path
import paho.mqtt.client as paho
import random
import sys
import time

# This is a client that carries out randomised behaviour. It is intended for
# use with the local config file. This file has multiple listeners configured:
#   * 1883 - unencrypted MQTT over TCP with no authentication
#   * 1884 - unencrypted MQTT over TCP with password authentication
#   * 1885 - unencrypted MQTT over TCP with plugin authentication
#   * 1886 - unencrypted MQTT over TCP with password and plugin authentication
#
#   * 8883 - encrypted MQTT over TCP with no authentication
#   * 8884 - encrypted MQTT over TCP with password authentication
#   * 8885 - encrypted MQTT over TCP with plugin authentication
#   * 8886 - encrypted MQTT over TCP with password and plugin authentication
#
#   * 8000 - unencrypted MQTT over WebSockets with no authentication
#   * 8001 - unencrypted MQTT over WebSockets with password authentication
#   * 8002 - unencrypted MQTT over WebSockets with plugin authentication
#   * 8003 - unencrypted MQTT over WebSockets with password and plugin authentication
#
#   * 4430 - encrypted MQTT over WebSockets with no authentication
#   * 4431 - encrypted MQTT over WebSockets with password authentication
#   * 4432 - encrypted MQTT over WebSockets with plugin authentication
#   * 4433 - encrypted MQTT over WebSockets with password and plugin authentication
#
# The client randomly picks:
#   * A port out of the list
#   * Whether to use encryption
#   * Whether to use WebSockets
#   * Clean start or not
#   * Session expiry interval or not
#   * QoS to use when subscribing - topics "outgoing/[client id]/message" and "response/#"
#   * Lifetime of connection
# On a per publish message basis it chooses:
#   * QoS of message
#   * Topic of message "outgoing/[0-max client]/message"
#   * Retain
#   * Interval until next outgoing message

ports = [
        {"port":1883, "tls":False, "transport":"tcp", "auth":False},
        {"port":1884, "tls":False, "transport":"tcp", "auth":True},
        {"port":1885, "tls":False, "transport":"tcp", "auth":True},
        {"port":1886, "tls":False, "transport":"tcp", "auth":True},

        {"port":8883, "tls":True, "transport":"tcp", "auth":False},
        {"port":8884, "tls":True, "transport":"tcp", "auth":True},
        {"port":8885, "tls":True, "transport":"tcp", "auth":True},
        {"port":8886, "tls":True, "transport":"tcp", "auth":True},

        {"port":8000, "tls":False, "transport":"websockets", "auth":False},
        {"port":8001, "tls":False, "transport":"websockets", "auth":True},
        {"port":8002, "tls":False, "transport":"websockets", "auth":True},
        {"port":8003, "tls":False, "transport":"websockets", "auth":True},

        {"port":4430, "tls":True, "transport":"websockets", "auth":False},
        {"port":4431, "tls":True, "transport":"websockets", "auth":True},
        {"port":4432, "tls":True, "transport":"websockets", "auth":True},
        {"port":4433, "tls":True, "transport":"websockets", "auth":True},
        ]

booleans = [True, False]
qos_values = [0, 1, 2]


def on_connect(client, userdata, flags, rc):
    global running
    if rc == 0:
        client.subscribe("response/#", subscribe_qos)
        client.subscribe("outgoing/%s/message" % (client_id), subscribe_qos)
    else:
        running = False


def on_message(client, userdata, msg):
    pass


def on_publish(client, userdata, mid):
    pass


def on_disconnect(client, userdata, rc):
    running = False


def do_publish(client):
    retain = random.choice(booleans)
    qos = random.choice(qos_values)
    topic = "outgoing/%d/message" % (random.uniform(1, 1000))
    payload = "message"

    client.publish(topic, payload, qos, retain)

    next_publish_time = time.time() + random.uniform(0.1, 2.0)


def main():
    global running
    global lifetime

    mqttc = paho.Client(client_id, clean_session=clean_start, protocol=protocol, transport=transport)
    mqttc.on_message = on_message
    mqttc.on_publish = on_publish
    mqttc.on_connect = on_connect
    mqttc.on_disconnect = on_disconnect
    if auth and random.choice(booleans):
        if random.choice(booleans):
            mqttc.username_pw_set("test", "password")
        else:
            mqttc.username_pw_set("bad", "bad")

    if use_tls:
        source_dir = Path(__file__).resolve().parent
        ssl_dir = source_dir.parent / "ssl"
        mqttc.tls_set(ca_certs=f"{ssl_dir}/all-ca.crt")

    mqttc.connect("localhost", port)
    mqttc.loop_start()

    while running:
        time.sleep(0.1)
        now = time.time()
        if now > next_publish_time:
            do_publish(mqttc)
        if now > lifetime:
            if random.choice(booleans):
                mqttc.disconnect()
                lifetime += 5.0
            else:
                running = False


p = random.choice(ports)
port = p["port"]
use_tls = p["tls"]
transport = p["transport"]
auth = p["auth"]

client_id = "cid"+sys.argv[1]
clean_start = random.choice(booleans)
subscribe_qos = random.choice(qos_values)
protocol = paho.MQTTv311
next_publish_time = time.time() + random.uniform(0.1, 2.0)
lifetime = time.time() + random.uniform(5.0, 10.0)
running = True

main()
