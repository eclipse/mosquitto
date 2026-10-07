#!/usr/bin/env python3

# Does a bridge queue up messages correctly if the remote broker starts up late?

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, MQTTBridgeConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])


def do_test(proto_ver):
    if proto_ver == 4:
        bridge_protocol = "mqttv311"
        proto_ver_connect = 128+4
    else:
        bridge_protocol = "mqttv50"
        proto_ver_connect = 5

    client_id = socket.gethostname()+".bridge_sample"
    connect_packet = mqtt_packets.gen_connect(client_id, clean_session=False, proto_ver=proto_ver_connect)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    c_connect_packet = mqtt_packets.gen_connect("client", proto_ver=proto_ver)
    c_connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    publish_packet = mqtt_packets.gen_publish("bridge/test", qos=1, mid=mid, payload="message", proto_ver=proto_ver)
    puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)

    (port1, port2) = mosq_test.get_port(2)

    ssock = mosq_test.listen_sock(port1)

    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port2) ],
        bridges = [MQTTBridgeConfig(
            connection="bridge_sample",
            address=f"localhost:{port1}",
            bridge_attempt_unsubscribe=False,
            bridge_max_topic_alias=0,
            bridge_protocol_version=bridge_protocol,
            notifications=False,
            topics=["bridge/# out 1"],
        )],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        (bridge, address) = ssock.accept()
        bridge.settimeout(20)

        client = mosq_test.do_client_connect(c_connect_packet, c_connack_packet, timeout=20, port=port2)
        mosq_test.do_send_receive(client, publish_packet, puback_packet, "puback")
        client.close()
        # We've now sent a message to the broker that should be delivered to us via the bridge

        mosq_test.expect_packet(bridge, "connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "publish", publish_packet)
        bridge.close()


do_test(proto_ver=4)
do_test(proto_ver=5)
