#!/usr/bin/env python3

# Test topic subscription. All topic are allowed but not using wildcard in subscribe.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

def do_test(plugin_ver):
    connect_packet = mqtt_packets.gen_connect("connect-uname-pwd-test", username="readonly")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    mid = 53
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "qos0/test", 0)
    suback_packet = mqtt_packets.gen_suback(mid, 0)

    mid_fail = 54
    subscribe_packet_fail = mqtt_packets.gen_subscribe(mid_fail, "#", 0)
    if plugin_ver == 2:
        suback_packet_fail = mqtt_packets.gen_suback(mid_fail, 0)
    else:
        suback_packet_fail = mqtt_packets.gen_suback(mid_fail, 0x80)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        plugins = [
            PluginConfig(
                path=mosq_paths.test_plugin(f'auth_plugin_v{plugin_ver}'),
            )
        ],
        allow_anonymous=False,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        mosq_test.do_send_receive(sock, subscribe_packet_fail, suback_packet_fail, "suback")
        sock.close()

do_test(2)
do_test(3)
do_test(4)
do_test(5)
