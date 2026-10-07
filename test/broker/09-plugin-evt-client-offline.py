#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

def do_test():
    connect_packet = mqtt_packets.gen_connect("plugin-evt-subscribe", proto_ver=4, clean_session=False)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=4)

    publish_packet = mqtt_packets.gen_publish("evt/client/offline", qos=0, payload="plugin-evt-subscribe")

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        plugins = [ PluginConfig(path=mosq_paths.test_plugin('plugin_evt_client_offline')) ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sub_sock = mosq_test.sub_helper(port, '#')

        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        sock.close()

        mosq_test.expect_packet(sub_sock, "publish", publish_packet)
        sub_sock.close()


do_test()
