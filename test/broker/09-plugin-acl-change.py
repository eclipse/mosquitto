#!/usr/bin/env python3

# A clean start=False client connects, and publishes to a topic it has access
# to with QoS 2 - but does not send a PUBREL. It closes the connection. The
# access to the topic is revoked, the client reconnects and it attempts to
# complete the flow. Is the publish allowed? It should not be.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

def do_test(plugin_ver):
    connect1_packet = mqtt_packets.gen_connect("acl-change-test", clean_session=False)
    connack1_packet = mqtt_packets.gen_connack(rc=0)

    connect2_packet = mqtt_packets.gen_connect("acl-change-test", clean_session=False)
    connack2_packet = mqtt_packets.gen_connack(rc=0,flags=1)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "#", 0)
    suback_packet = mqtt_packets.gen_suback(mid, 0)

    mid = 2
    publish1_packet = mqtt_packets.gen_publish("publish/topic", qos=2, mid=mid, payload="message")
    pubrec1_packet = mqtt_packets.gen_pubrec(mid)
    pubrel1_packet = mqtt_packets.gen_pubrel(mid)
    pubcomp1_packet = mqtt_packets.gen_pubcomp(mid)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        plugins = [
            PluginConfig(path=mosq_paths.test_plugin('auth_plugin_acl_change'))
        ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback 1")
        mosq_test.do_send_receive(sock, publish1_packet, pubrec1_packet, "pubrec")
        sock.close()

        # ACL has changed
        sock = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback 2")
        mosq_test.do_send_receive(sock, pubrel1_packet, pubcomp1_packet, "pubcomp")
        mosq_test.do_ping(sock)
        sock.close()
