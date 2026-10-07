#!/usr/bin/env python3

# Test whether a connection is denied if it provides a correct username but
# incorrect password.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_TLS"])

def do_test(proto_ver):
    connect_packet = mqtt_packets.gen_connect("connect-uname-pwd-test", username="user", password="password", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        allow_anonymous=False,
        password_file=os.path.basename(__file__).replace('.py', '.pwfile'),
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        sock.close()


do_test(proto_ver=4)
do_test(proto_ver=5)
