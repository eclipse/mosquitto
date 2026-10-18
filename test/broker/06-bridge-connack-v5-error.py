#!/usr/bin/env python3

# Does a bridge honour retain-available

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, MQTTBridgeConfig
from matchers import Contains
from mosquitto_broker import MosquittoBroker
import mqtt4_rc

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])

def do_test(rc, logmsg):
    hostname = socket.gethostname()
    client_id = hostname+".bridge_sample"
    connect_packet = mqtt_packets.gen_connect(client_id, clean_session=False, proto_ver=5, will_topic=f"$SYS/broker/connection/{hostname}.bridge_sample/state", will_payload=b"0", will_qos=1, will_retain=True)
    connack_packet = mqtt_packets.gen_connack(rc=rc, proto_ver=5)

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
            ),
        ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        (bridge, address) = ssock.accept()
        bridge.settimeout(20)
        mosq_test.expect_packet(bridge, "connect", connect_packet)
        bridge.send(connack_packet)
        bridge.close()

    broker.check_log(Contains(logmsg))

do_test(mqtt5_rc.BAD_USERNAME_OR_PASSWORD, "Connection Refused: Bad User Name or Password")
