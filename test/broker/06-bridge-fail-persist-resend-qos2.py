#!/usr/bin/env python3

# Test whether a bridge can cope with an unknown PUBACK

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, MQTTBridgeConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])


def do_test(proto_ver):
    if proto_ver == 4:
        bridge_protocol = "mqttv311"
        proto_ver_connect = 4
    else:
        bridge_protocol = "mqttv50"
        proto_ver_connect = 5

    connect_packet = mqtt_packets.gen_connect("bridge-u-test", proto_ver=proto_ver_connect)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 180
    mid_unknown = 2000

    publish_packet = mqtt_packets.gen_publish("bridge/unknown/qos2", qos=1, payload="bridge-message", mid=mid, proto_ver=proto_ver)
    puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)

    pubrec_packet_unknown1 = mqtt_packets.gen_pubrec(mid_unknown+1, proto_ver=proto_ver)
    pubrel_packet_unknown1 = mqtt_packets.gen_pubrel(mid_unknown+1, proto_ver=proto_ver)

    pubrel_packet_unknown2 = mqtt_packets.gen_pubrel(mid_unknown+2, proto_ver=proto_ver)
    pubcomp_packet_unknown2 = mqtt_packets.gen_pubcomp(mid_unknown+2, proto_ver=proto_ver)

    pubcomp_packet_unknown3 = mqtt_packets.gen_pubcomp(mid_unknown+3, proto_ver=proto_ver)


    unsubscribe_packet = mqtt_packets.gen_unsubscribe(1, "bridge/#", proto_ver=proto_ver)
    unsuback_packet = mqtt_packets.gen_unsuback(1, proto_ver=proto_ver)

    (port1, port2) = mosq_test.get_port(2)

    sock = mosq_test.listen_sock(port1)

    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port2) ],
        bridges = [
            MQTTBridgeConfig(
                connection="bridge-u-test",
                remote_clientid="bridge-u-test",
                address=f"localhost:{port1}",
                topics=["bridge/# out"],
                cleansession=True,
                notifications=False,
                restart_timeout=5,
                try_private=False,
                bridge_protocol_version=bridge_protocol,
                bridge_max_topic_alias=0,
            ),
        ]
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        (conn, address) = sock.accept()
        conn.settimeout(20)

        mosq_test.expect_packet(conn, "connect", connect_packet)
        conn.send(connack_packet)

        mosq_test.expect_packet(conn, "unsubscribe", unsubscribe_packet)
        conn.send(unsuback_packet)

        # Send the unexpected pubrec packet
        conn.send(pubrec_packet_unknown1)
        mosq_test.expect_packet(conn, "pubrel", pubrel_packet_unknown1)

        conn.send(pubrel_packet_unknown2)
        mosq_test.expect_packet(conn, "pubcomp", pubcomp_packet_unknown2)

        conn.send(pubcomp_packet_unknown3)

        # Send a legitimate publish packet to verify everything is still ok
        conn.send(publish_packet)

        mosq_test.expect_packet(conn, "puback", puback_packet)


do_test(proto_ver=4)
do_test(proto_ver=5)
