#!/usr/bin/env python3

# Test whether sending a non zero session expiry interval in DISCONNECT after
# having sent a zero session expiry interval is treated correctly in MQTT v5.

from mosq_test_helper import *

from broker_config import BrokerConfig
from mosquitto_broker import MosquittoBroker

keepalive = 61
connect_packet = mqtt_packets.gen_connect("12-server-keepalive", proto_ver=5, keepalive=keepalive)

props = mqtt5_props.gen_uint16_prop(mqtt5_props.SERVER_KEEP_ALIVE, 60) \
        + mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS_MAXIMUM, 10) \
        + mqtt5_props.gen_uint32_prop(mqtt5_props.MAXIMUM_PACKET_SIZE, 2000000) \
        + mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 20)
connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=props, property_helper=False)

port = mosq_test.get_port()
broker_config = BrokerConfig(max_keepalive=60)
broker = MosquittoBroker(port=port, config=broker_config)
with broker:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    sock.close()
