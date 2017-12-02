#!/usr/bin/env python

# Test whether a patter subscribe match or not $SYS
import subprocess
import threading
import time

try:
    import paho.mqtt.client
except ImportError:
    print("WARNING: paho.mqtt module not available, skipping pattern matching $SYS")
    exit(0)


rc = 1

broker = subprocess.Popen(['../../src/mosquitto', '-p', '1888'], stderr=subprocess.PIPE)
# Wait for broker to start
time.sleep(1)


def wait_sys_msg(topic="$SYS/#"):
    """ Connect a client and wait for any message on $SYS
    """
    def on_sys_message(client, userdata, msg):
        assert msg.topic.startswith('$SYS/')
        client.disconnect()

    client = paho.mqtt.client.Client("sys-monitor")
    client.connect("localhost", port=1888)
    client.message_callback_add("$SYS/#", on_sys_message)
    client.subscribe("$SYS/broker/publish/messages/dropped")
    client.loop_forever()


def test_pattern(sub_topic, sys_topic="$SYS/#"):
    msgs = []
    sub_finished = threading.Event()
    def on_message(client, userdata, msg):
        msgs.append(msg)

    def on_subscribe(client, userdata, mid, granted_qos):
        sub_finished.set()

    client = paho.mqtt.client.Client("pattern-matching-sys", userdata=msgs)
    client.connect("localhost", port=1888)
    client.on_message = on_message
    client.on_subscribe = on_subscribe
    client.subscribe(sub_topic, qos=1)
    client.loop_start()

    sub_finished.wait(5)
    assert sub_finished.is_set(), "subscribe timedout"
    wait_sys_msg()
    client.loop_stop()
    for m in msgs:
        if m.topic.startswith("$SYS"):
            print("Received message on topic %s" % m.topic)
            return False
    return True


try:
    assert test_pattern("#")
    assert test_pattern("+/#")

    # $SYS/broker/version or $SYS/broker/uptime, ...
    assert test_pattern("+/broker/+", '$SYS/broker/+')
    assert test_pattern("+/+/+", '$SYS/+/+')

    rc = 0
finally:
    broker.terminate()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde)

exit(rc)

