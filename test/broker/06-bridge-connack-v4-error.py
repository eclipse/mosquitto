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
    connect_packet = mqtt_packets.gen_connect(client_id, clean_session=False, proto_ver=128+4, will_topic=f"$SYS/broker/connection/{hostname}.bridge_sample/state", will_payload=b"0", will_qos=1, will_retain=True)
    connack_packet = mqtt_packets.gen_connack(rc=rc, proto_ver=4)

    (port1, port2) = mosq_test.get_port(2)

    ssock = mosq_test.listen_sock(port1)

    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port2) ],
        bridges = [
            MQTTBridgeConfig(
                connection="bridge_sample",
                address=f"localhost:{port1}",
                bridge_protocol_version="mqttv311",
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
        bridge.recv(1)
        bridge.close()

    broker.check_log(Contains(logmsg))

do_test(mqtt4_rc.CONNACK_REFUSED_SERVER_UNAVAILABLE, "Connection Refused: broker unavailable")
do_test(mqtt4_rc.CONNACK_REFUSED_BAD_USERNAME_PASSWORD, "Connection Refused: bad user name or password")
do_test(mqtt4_rc.CONNACK_REFUSED_NOT_AUTHORIZED, "Connection Refused: not authorised")
do_test(mqtt4_rc.CONNACK_REFUSED_IDENTIFIER_REJECTED, "Connection Refused: identifier rejected")
do_test(mqtt4_rc.CONNACK_REFUSED_PROTOCOL_VERSION, "Connection Refused: unacceptable protocol version")
do_test(128, "Connection Refused: unknown reason")
