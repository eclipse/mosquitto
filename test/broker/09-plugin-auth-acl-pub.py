#!/usr/bin/env python3

# Bug specific test - if a QoS2 publish is denied, then we publish again with
# the same mid to a topic that is allowed, does it work properly?

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

def do_test(plugin_ver):
    connect1_packet = mqtt_packets.gen_connect("connect-uname-pwd-test", username="readwrite", clean_session=False)
    connack1_packet = mqtt_packets.gen_connack(rc=0)

    connect2_packet = mqtt_packets.gen_connect("connect-uname-pwd-test", username="readwrite", clean_session=False)
    connack2_packet = mqtt_packets.gen_connack(rc=0,flags=1)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "readonly", 2)
    suback_packet = mqtt_packets.gen_suback(mid, 2)

    mid = 2
    publish1_packet = mqtt_packets.gen_publish("readonly", qos=2, mid=mid, payload="message")
    pubrec1_packet = mqtt_packets.gen_pubrec(mid)
    pubrel1_packet = mqtt_packets.gen_pubrel(mid)
    pubcomp1_packet = mqtt_packets.gen_pubcomp(mid)

    mid = 2
    publish2_packet = mqtt_packets.gen_publish("writeable", qos=1, mid=mid, payload="message")
    puback2_packet = mqtt_packets.gen_puback(mid)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        plugins = [
            PluginConfig(path=mosq_paths.test_plugin(f'auth_plugin_v{plugin_ver}'))
        ],
        allow_anonymous=False,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, publish1_packet, pubrec1_packet, "pubrec1")
        sock.close()

        sock = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, publish2_packet, puback2_packet, "puback2")

        mosq_test.do_ping(sock)
        sock.close()

do_test(2)
do_test(3)
do_test(4)
do_test(5)
