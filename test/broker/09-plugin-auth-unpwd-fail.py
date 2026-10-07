#!/usr/bin/env python3

# Test whether a connection is successful with correct username and password
# when using a simple auth_plugin.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker


def do_test(plugin_ver):
    connect_packet = mqtt_packets.gen_connect("connect-uname-pwd-test", username="test-username", password="wrong")
    connack_packet = mqtt_packets.gen_connack(rc=5)

    connect_packet_binary_pw1 = mqtt_packets.gen_connect("connect-uname-pwd-test", username="binary-password", password="\x00\x01\x02\x03\x04\x05\x06\x08")
    connect_packet_binary_pw2 = mqtt_packets.gen_connect("connect-uname-pwd-test", username="binary-password", password="\x00\x01\x02\x03\x04\x05\x06")

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        plugins = [ PluginConfig(path=mosq_paths.test_plugin(f'auth_plugin_v{plugin_ver}')) ],
        allow_anonymous=False,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        sock.close()

        if plugin_ver == 5:
            sock = mosq_test.do_client_connect(connect_packet_binary_pw1, connack_packet, port=port)
            sock.close()
            sock = mosq_test.do_client_connect(connect_packet_binary_pw2, connack_packet, port=port)
            sock.close()


do_test(4)
do_test(5)
