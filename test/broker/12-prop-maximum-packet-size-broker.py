#!/usr/bin/env python3

# Check whether the broker disconnects a client nicely when they send a too large packet.

from mosq_test_helper import *

from broker_config import BrokerConfig
from mosquitto_broker import MosquittoBroker

connect_packet = mqtt_packets.gen_connect("12-max-packet-broker", proto_ver=5)
props = mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS_MAXIMUM, 10)
props += mqtt5_props.gen_uint32_prop(mqtt5_props.MAXIMUM_PACKET_SIZE, 50)
props += mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 20)
connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=props, property_helper=False)

publish_packet_ok = mqtt_packets.gen_publish("12/max/packet/size/broker/test/topic", qos=0, payload="012345678", proto_ver=5)
publish_packet_bad = mqtt_packets.gen_publish("12/max/packet/size/broker/test/topic", qos=0, payload="0123456789", proto_ver=5)
disconnect_packet = mqtt_packets.gen_disconnect(reason_code=149, proto_ver=5)

port = mosq_test.get_port()
broker_config = BrokerConfig(max_packet_size=50)
broker = MosquittoBroker(port=port, config=broker_config)
with broker:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    sock.send(publish_packet_ok)
    mosq_test.do_ping(sock)
    mosq_test.do_send_receive(sock, publish_packet_bad, disconnect_packet, "disconnect")
