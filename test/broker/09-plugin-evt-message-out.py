#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

def do_test():
    connect_packet = mqtt_packets.gen_connect("plugin-evt-message-out", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "#", 2, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 2, proto_ver=5)

    publish_packet_deny = mqtt_packets.gen_publish("deny", qos=0, payload="message1", proto_ver=5)

    props = mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "response/topic")
    publish_packet1 = mqtt_packets.gen_publish("out-topic", qos=0, payload="message1", proto_ver=5, properties=props)

    props = mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key", "value")
    publish_packet2 = mqtt_packets.gen_publish("new-topic", qos=0, payload="new-message", proto_ver=5, properties=props)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        plugins = [ PluginConfig(path=mosq_paths.test_plugin('plugin_evt_message_out')) ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock.send(publish_packet_deny)
        mosq_test.do_ping(sock)

        sock.send(publish_packet1)
        mosq_test.expect_packet(sock, "publish2", publish_packet2)
        mosq_test.do_ping(sock)
        sock.close()

do_test()
