#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker


connect_packet = mqtt_packets.gen_connect("connect-uname-pwd-test", username="test-username", password="wrong")
connack_packet = mqtt_packets.gen_connack(rc=5)

port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners = [ ListenerConfig(port=port) ],
    plugins = [ PluginConfig(path=mosq_paths.test_plugin('auth_plugin_v5')) ],
    allow_anonymous=False,
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
    sock.close()
