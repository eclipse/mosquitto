#!/usr/bin/env python3

# Check that bridge notification payloads can be configured, including spaces.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, MQTTBridgeConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])


def do_test():
    hostname = socket.gethostname()
    client_id = hostname+".bridge_sample"

    payload_up = "bridge is up"
    payload_down = "bridge is down"
    topic = f"$SYS/broker/connection/{client_id}/state"

    connect_packet = mqtt_packets.gen_connect(
        client_id,
        clean_session=False,
        proto_ver=5,
        will_topic=topic,
        will_payload=payload_down.encode(),
        will_qos=1,
        will_retain=True,
    )
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    publish_packet = mqtt_packets.gen_publish(
        topic,
        qos=1,
        mid=1,
        payload=payload_up,
        retain=True,
        proto_ver=5,
    )
    puback_packet = mqtt_packets.gen_puback(1, proto_ver=5)

    (port1, port2) = mosq_test.get_port(2)
    ssock = mosq_test.listen_sock(port1)

    broker_config = BrokerConfig(
        listeners=[ListenerConfig(port=port2)],
        bridges=[
            MQTTBridgeConfig(
                connection="bridge_sample",
                address=f"localhost:{port1}",
                bridge_protocol_version="mqttv50",
                bridge_max_topic_alias=0,
                notification_payload_up=payload_up,
                notification_payload_down=payload_down,
                topics=["\"bridge with space/#\" both 1"],
            ),
        ],
        allow_anonymous=True,
    )

    broker = MosquittoBroker(config=broker_config)
    with broker:
        (bridge, _) = ssock.accept()
        bridge.settimeout(20)
        mosq_test.expect_packet(bridge, "connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "publish", publish_packet)
        bridge.send(puback_packet)
        bridge.close()


do_test()

