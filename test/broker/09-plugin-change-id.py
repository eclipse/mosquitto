#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

def do_test(plugin_ver):
    connect1_packet = mqtt_packets.gen_connect("already-exists")
    connack1_packet = mqtt_packets.gen_connack(rc=0)

    connect2_packet = mqtt_packets.gen_connect("id-change-test")
    connack2_packet = mqtt_packets.gen_connack(rc=0)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "#", 0)
    # Only subs by client id == allowed is allowed
    suback_packet_denied = mqtt_packets.gen_suback(mid, 128)
    suback_packet_ok = mqtt_packets.gen_suback(mid, 0)

    mid = 2
    publish1_packet = mqtt_packets.gen_publish("publish/topic", qos=2, mid=mid, payload="message")
    pubrec1_packet = mqtt_packets.gen_pubrec(mid)
    pubrel1_packet = mqtt_packets.gen_pubrel(mid)
    pubcomp1_packet = mqtt_packets.gen_pubcomp(mid)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        plugins = [ PluginConfig(path=mosq_paths.test_plugin('auth_plugin_id_change')) ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=20, port=port)
        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet_denied, "suback denied")
        mosq_test.do_send_receive(sock2, subscribe_packet, suback_packet_ok, "suback ok")

        mosq_test.do_ping(sock1)
        mosq_test.do_ping(sock2)
        sock1.close()
        sock2.close()


do_test(4)
