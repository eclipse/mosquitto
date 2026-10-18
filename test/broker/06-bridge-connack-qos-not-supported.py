#!/usr/bin/env python3

# Does a bridge honour retain-available

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, MQTTBridgeConfig
from matchers import Contains
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])

def do_test():
    hostname = socket.gethostname()
    client_id = hostname+".bridge_sample"
    connect_packet_qos1 = mqtt_packets.gen_connect(client_id, clean_session=False, proto_ver=5, will_topic=f"$SYS/broker/connection/{hostname}.bridge_sample/state", will_payload=b"0", will_qos=1, will_retain=True)
    connect_packet_qos0 = mqtt_packets.gen_connect(client_id, clean_session=False, proto_ver=5, will_topic=f"$SYS/broker/connection/{hostname}.bridge_sample/state", will_payload=b"0", will_qos=0, will_retain=True)

    props = mqtt5_props.gen_byte_prop(mqtt5_props.MAXIMUM_QOS, 0)
    connack_packet_qos1 = mqtt_packets.gen_connack(rc=mqtt5_rc.QOS_NOT_SUPPORTED, proto_ver=5, properties=props)
    connack_packet_qos0 = mqtt_packets.gen_connack(rc=mqtt5_rc.QOS_NOT_SUPPORTED, proto_ver=5, properties=props)

    (port1, port2) = mosq_test.get_port(2)

    ssock = mosq_test.listen_sock(port1)

    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port2) ],
        bridges = [
            MQTTBridgeConfig(
                connection="bridge_sample",
                address=f"localhost:{port1}",
                bridge_protocol_version="mqttv50",
                topics=["\"bridge with space/#\" both 1"],
                bridge_max_topic_alias=0,
                restart_timeout=1,
            ),
        ],
        allow_anonymous=True,
        maximum_qos=0,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        # Connect with a will with QoS=1, get refused
        (bridge, address) = ssock.accept()
        bridge.settimeout(20)
        mosq_test.expect_packet(bridge, "connect", connect_packet_qos1)
        bridge.send(connack_packet_qos1)
        bridge.close()

        # Now retry with QoS=0
        (bridge, address) = ssock.accept()
        bridge.settimeout(20)
        mosq_test.expect_packet(bridge, "connect", connect_packet_qos0)
        bridge.send(connack_packet_qos0)
        bridge.close()

    broker.check_log(Contains("Connection Refused: QoS not supported (will retry)"))

do_test()
