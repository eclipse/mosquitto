#!/usr/bin/env python3

# Test whether a connection is denied if it provides a correct username but
# incorrect password.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_TLS"])

def do_test(proto_ver):
    connect_packet = mqtt_packets.gen_connect("connect-uname-pwd-test", username="user", password="password9", proto_ver=proto_ver)
    if proto_ver == 5:
        connack_packet = mqtt_packets.gen_connack(rc=mqtt5_rc.NOT_AUTHORIZED, proto_ver=proto_ver, properties=None)
    else:
        connack_packet = mqtt_packets.gen_connack(rc=5, proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        allow_anonymous=False,
        password_file=Path(__file__).resolve().parent / os.path.basename(__file__).replace('.py', '.pwfile'),
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        sock.close()


do_test(proto_ver=4)
do_test(proto_ver=5)
