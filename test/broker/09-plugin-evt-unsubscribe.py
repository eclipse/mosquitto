#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

def do_test():
    rc = 1
    connect_packet = mqtt_packets.gen_connect("plugin-evt-unsubscribe", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "unsubscribe-topic", 1, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=5)

    mid = 2
    unsubscribe_packet = mqtt_packets.gen_unsubscribe(mid, "unsubscribe-topic", proto_ver=5)
    unsuback_packet = mqtt_packets.gen_unsuback(mid, mqtt5_rc.NO_SUBSCRIPTION_EXISTED, proto_ver=5)

    publish_packet = mqtt_packets.gen_publish("unsubscribe-topic", qos=0, payload="message1", proto_ver=5)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        plugins = [ PluginConfig(path=mosq_paths.test_plugin('plugin_evt_unsubscribe')) ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        mosq_test.do_send_receive(sock, unsubscribe_packet, unsuback_packet, "unsuback")
        mosq_test.do_send_receive(sock, publish_packet, publish_packet, "publish")
        sock.close()


do_test()
