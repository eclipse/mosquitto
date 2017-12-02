#!/usr/bin/env python

# Test whether a pattern subscribe match or not $SYS
import Queue
import subprocess
import threading
import time

try:
    import paho.mqtt.client
except ImportError:
    print("WARNING: paho.mqtt module not available, skipping pattern matching $SYS")
    exit(0)


import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test


rc = 1

broker = mosq_test.start_broker(filename=os.path.basename(__file__))
# Wait for broker to start
time.sleep(1)


sys_client = 'client-sys'

clients_config = [
    # client-id, topic
    (sys_client, '$SYS/broker/uptime'),
    ('client1', '#'),
    ('client2', '+/+/+'),
    ('client3', '+/#'),
]


msgs = Queue.Queue()

(stdo1, stde1) = ("", "")
try:
    clients = []
    def on_message(client, userdata, msg):
        msgs.put((userdata, msg))

    for (client_id, topic) in clients_config:
        client = paho.mqtt.client.Client(
            client_id, userdata=client_id, clean_session=False,
        )
        client.connect("localhost", port=1888)
        client.on_message = on_message
        client.subscribe(topic, qos=1)
        client.loop_start()

    # Wait for connection and subscription
    time.sleep(3)

    broker.terminate()
    broker.wait()
    (stdo1, stde1) = broker.communicate()
    broker = None

    try:
        sys_has_message = False
        while True:
            (client_id, msg) = msgs.get_nowait()
            if msg.topic.startswith("$SYS"):
                if client_id != sys_client:
                    raise ValueError("Received message on topic %s" % msg.topic)
                else:
                    sys_has_message = True
    except Queue.Empty:
        pass
    assert sys_has_message

    broker = mosq_test.start_broker(filename=os.path.basename(__file__))

    try:
        sys_has_message = False
        while True:
            (client_id, msg) = msgs.get(timeout=5)
            if msg.topic.startswith("$SYS"):
                if client_id != sys_client:
                    raise ValueError("Received message on topic %s" % msg.topic)
                else:
                    sys_has_message = True
    except Queue.Empty:
        pass
    assert sys_has_message
    rc = 0
finally:
    if broker:
        broker.terminate()
        (stdo, stde) = broker.communicate()
    else:
        stde = ""
    if rc:
        print(stde1 + stde)
    if os.path.exists('mosquitto-test.db'):
        os.unlink('mosquitto-test.db')

exit(rc)

