#!/usr/bin/env python

# Test whether a Kafka connection works. Needs a running Kafka broker at localhost:9092 (use
# 11-kafka-bridge_kafka.conf and 11-kafka-bridge_zookeeper.properties).
# Dependencies: kafka-python (http://kafka-python.readthedocs.io/)
#               Paho Python client (https://www.eclipse.org/paho/clients/python/)

import inspect, os, sys

# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],'..')))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test, logging
import paho.mqtt.publish as publish
from kafka import KafkaConsumer

rc = 1
keepalive = 10
broker = mosq_test.start_broker(filename=os.path.basename(__file__))

# create a Kafka consumer
logging.getLogger('kafka').addHandler(logging.NullHandler())
consumer = KafkaConsumer('test.kafka', bootstrap_servers=['localhost:9092'], consumer_timeout_ms=10)

messages = []
try:
    for qos in range(3):
        messages.append("Test message (QoS %d)" % (qos, ))
        publish.single("test/kafka", messages[-1], hostname="localhost", port=1888, qos=qos)
    rc = 0
finally:
    broker.terminate()
    broker.wait()
    if rc:
        (stdo, stde) = broker.communicate()
        print(stde)

# validate message sent to Kafka
receivedMessages = consumer.poll(1000)
for i in range(len(messages)):
    received = receivedMessages.values()[0][i]
    if received.value != messages[i] or received.topic != 'test.kafka':
        print 'Test message was not correctly transmitted to Kafka consumer, received: {0}'.format(received)
        rc = 1

consumer.close()
exit(rc)

