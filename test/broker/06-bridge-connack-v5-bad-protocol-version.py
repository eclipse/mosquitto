#!/usr/bin/env python3

# Does a bridge honour retain-available

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, MQTTBridgeConfig
from matchers import Contains
from mosquitto_broker import MosquittoBroker
import mqtt4_rc

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])

def do_test():
    hostname = socket.gethostname()
    client_id = hostname+".bridge_sample"
    connect_packet_v5 = mqtt_packets.gen_connect(client_id, clean_session=False, proto_ver=5, will_topic=f"$SYS/broker/connection/{hostname}.bridge_sample/state", will_payload=b"0", will_qos=1, will_retain=True)
    connect_packet_v4 = mqtt_packets.gen_connect(client_id, clean_session=False, proto_ver=128+4, will_topic=f"$SYS/broker/connection/{hostname}.bridge_sample/state", will_payload=b"0", will_qos=1, will_retain=True)

    connack_packet_v4_denied = mqtt_packets.gen_connack(rc=mqtt4_rc.CONNACK_REFUSED_PROTOCOL_VERSION, proto_ver=4)
    connack_packet_v4_accepted = mqtt_packets.gen_connack(rc=mqtt4_rc.CONNACK_REFUSED_PROTOCOL_VERSION, proto_ver=4)

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
        retain_available=False,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        # Connect with v5
        (bridge, address) = ssock.accept()
        bridge.settimeout(20)
        mosq_test.expect_packet(bridge, "connect", connect_packet_v5)
        bridge.send(connack_packet_v4_denied)
        bridge.close()

        # Now retry with v4
        (bridge, address) = ssock.accept()
        bridge.settimeout(20)
        mosq_test.expect_packet(bridge, "connect", connect_packet_v4)
        bridge.send(connack_packet_v4_accepted)
        bridge.close()

    broker.check_log(Contains("Warning: Remote bridge bridge_sample does not support MQTT v5.0, reconnecting using MQTT v3.1.1."))

do_test()
