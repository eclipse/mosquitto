#!/usr/bin/env python3

# Test whether a PUBLISH to a topic with an offline subscriber results in a queued message
import Queue
import random
import string
import subprocess
import socket
import threading
import time

try:
    import paho.mqtt.client
    import paho.mqtt.publish
except ImportError:
    print("WARNING: paho.mqtt module not available, skipping byte count test.")
    exit(0)


from mosq_test_helper import *

rc = 1

port = mosq_test.get_port()

def registerOfflineSubscriber():
    """Just a durable client to trigger queuing"""
    client = paho.mqtt.client.Client("sub-qos1-offline", clean_session=False)
    client.connect("localhost", port=port)
    client.subscribe("test/publish/queueing/#", 1)
    client.loop()
    client.disconnect()


broker = MosquittoBroker(port=port)

class BrokerMonitor(threading.Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        threading.Thread.__init__(self, group=group, target=target, name=name, verbose=verbose)
        self.rq, self.cq = args
        self.stored = -1
        self.stored_bytes = -1
        self.dropped = -1

    def store_count(self, client, userdata, message):
        self.stored = int(message.payload)

    def store_bytes(self, client, userdata, message):
        self.stored_bytes = int(message.payload)

    def publish_dropped(self, client, userdata, message):
        self.dropped = int(message.payload)

    def run(self):
        client = paho.mqtt.client.Client("broker-monitor")
        client.connect("localhost", port=port)
        client.message_callback_add("$SYS/broker/store/messages/count", self.store_count)
        client.message_callback_add("$SYS/broker/store/messages/bytes", self.store_bytes)
        client.message_callback_add("$SYS/broker/publish/messages/dropped", self.publish_dropped)
        client.subscribe("$SYS/broker/store/messages/#")
        client.subscribe("$SYS/broker/publish/messages/dropped")

        while True:
            expect_drops = cq.get()
            self.cq.task_done()
            if expect_drops == "quit":
                break
            first = time.time()
            while self.stored < 0 or self.stored_bytes < 0 or (expect_drops and self.dropped < 0):
                client.loop(timeout=0.5)
                if time.time() - 10 > first:
                    print("ABORT TIMEOUT")
                    break

            if expect_drops:
                self.rq.put((self.stored, self.stored_bytes, self.dropped))
            else:
                self.rq.put((self.stored, self.stored_bytes, 0))
            self.stored = -1
            self.stored_bytes = -1
            self.dropped = -1

        client.disconnect()

rq = Queue.Queue()
cq = Queue.Queue()
brokerMonitor = BrokerMonitor(args=(rq,cq))

class StoreCounts():
    def __init__(self):
        self.stored = 0
        self.bstored = 0
        self.drops = 0
        self.diff_stored = 0
        self.diff_bstored = 0
        self.diff_drops = 0

    def update(self, tup):
        self.diff_stored = tup[0] - self.stored
        self.stored = tup[0]
        self.diff_bstored = tup[1] - self.bstored
        self.bstored = tup[1]
        self.diff_drops = tup[2] - self.drops
        self.drops = tup[2]

    def __repr__(self):
        return "s: %d (%d) b: %d (%d) d: %d (%d)" % (self.stored, self.diff_stored, self.bstored, self.diff_bstored, self.drops, self.diff_drops)

try:
    registerOfflineSubscriber()
    time.sleep(2.5)  # Wait for first proper dump of stats
    brokerMonitor.start()
    counts = StoreCounts()
    cq.put(True)  # Expect a dropped count (of 0, initial)
    counts.update(rq.get())  # Initial start
    print("rq.get (INITIAL) gave us: ", counts)
    rq.task_done()

    # publish 10 short messages, should be no drops
    print("publishing 10 short")
    cq.put(False)  # expect no updated drop count
    msgs_short10 = [("test/publish/queueing/%d" % x,
             ''.join(random.choice(string.hexdigits) for _ in range(10)),
             1, False) for x in range(1, 10 + 1)]
    paho.mqtt.publish.multiple(msgs_short10, port=port)
    counts.update(rq.get())  # Initial start
    print("rq.get (short) gave us: ", counts)
    rq.task_done()
    if counts.diff_stored != 10 or counts.diff_bstored < 100:
        raise ValueError
    if counts.diff_drops != 0:
        raise ValueError

    # publish 10 mediums (40bytes). should fail after 8, when it finally crosses 400
    print("publishing 10 medium")
    cq.put(True)  # expect a drop count
    msgs_medium10 = [("test/publish/queueing/%d" % x,
             ''.join(random.choice(string.hexdigits) for _ in range(40)),
             1, False) for x in range(1, 10 + 1)]
    paho.mqtt.publish.multiple(msgs_medium10, port=port)
    counts.update(rq.get())  # Initial start
    print("rq.get (medium) gave us: ", counts)
    rq.task_done()
    if counts.diff_stored != 8 or counts.diff_bstored < 320:
        raise ValueError
    if counts.diff_drops != 2:
        raise ValueError
    rc = 0

except mosq_test.TestError:
    pass
finally:
    cq.put("quit")
    brokerMonitor.join()
    rq.join()
    cq.join()
    mosq_test.terminate_broker(broker)
    if rc:
        print(mosq_test.broker_log(broker))

exit(rc)

