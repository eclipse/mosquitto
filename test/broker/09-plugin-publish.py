#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

proto_ver = 5

connect1_packet = mqtt_packets.gen_connect("test-client", username="readwrite", clean_session=False, proto_ver=proto_ver)
connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

publish_packet = mqtt_packets.gen_publish("init", qos=0, proto_ver=proto_ver)

publish0_packet = mqtt_packets.gen_publish("topic/0", qos=0, payload="test-message-0", proto_ver=proto_ver)

mid = 1
publish1_packet = mqtt_packets.gen_publish("topic/1", qos=1, mid=mid, payload="test-message-1", proto_ver=proto_ver)
puback1_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)

mid = 2
publish2_packet = mqtt_packets.gen_publish("topic/2", qos=2, mid=mid, payload="test-message-2", proto_ver=proto_ver)
pubrec2_packet = mqtt_packets.gen_pubrec(mid, proto_ver=proto_ver)
pubrel2_packet = mqtt_packets.gen_pubrel(mid, proto_ver=proto_ver)
pubcomp2_packet = mqtt_packets.gen_pubcomp(mid, proto_ver=proto_ver)


props = mqtt5_props.gen_byte_prop(mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 1)
publish0p_packet = mqtt_packets.gen_publish("topic/0", qos=0, payload="test-message-0", proto_ver=proto_ver, properties=props)

mid = 3
publish1p_packet = mqtt_packets.gen_publish("topic/1", qos=1, mid=mid, payload="test-message-1", proto_ver=proto_ver, properties=props)
puback1p_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)

mid = 4
publish2p_packet = mqtt_packets.gen_publish("topic/2", qos=2, mid=mid, payload="test-message-2", proto_ver=proto_ver, properties=props)
pubrec2p_packet = mqtt_packets.gen_pubrec(mid, proto_ver=proto_ver)
pubrel2p_packet = mqtt_packets.gen_pubrel(mid, proto_ver=proto_ver)
pubcomp2p_packet = mqtt_packets.gen_pubcomp(mid, proto_ver=proto_ver)

port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners = [ ListenerConfig(port=port) ],
    plugins = [ PluginConfig(path=mosq_paths.test_plugin('auth_plugin_publish')) ],
    allow_anonymous=True,
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=20, port=port)

    # Trigger the plugin to send us some messages
    sock.send(publish_packet)

    mosq_test.expect_packet(sock, "publish0", publish0_packet)
    mosq_test.expect_packet(sock, "publish1", publish1_packet)
    sock.send(puback1_packet)

    mosq_test.expect_packet(sock, "publish2", publish2_packet)
    mosq_test.do_send_receive(sock, pubrec2_packet, pubrel2_packet, "pubrel1")
    sock.send(pubcomp2_packet)

    # And trigger the second set of messages, with properties
    sock.send(publish_packet)
    mosq_test.expect_packet(sock, "publish0p", publish0p_packet)
    mosq_test.expect_packet(sock, "publish1p", publish1p_packet)
    sock.send(puback1_packet)

    mosq_test.expect_packet(sock, "publish2p", publish2p_packet)
    mosq_test.do_send_receive(sock, pubrec2p_packet, pubrel2p_packet, "pubrel1p")
    sock.send(pubcomp2p_packet)

    mosq_test.do_ping(sock)
    sock.close()
