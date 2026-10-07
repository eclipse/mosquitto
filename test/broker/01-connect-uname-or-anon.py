#!/usr/bin/env python3

# Test whether an anonymous connection is correctly denied.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_TLS"])

def do_test(allow_anonymous, password_file, username, expect_success):
    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        allow_anonymous=allow_anonymous,
    )
    if password_file:
        broker_config.password_file = Path(__file__).resolve().parent / os.path.basename(__file__).replace('.py', '.pwfile')

    broker = MosquittoBroker(config=broker_config)
    with broker:
        for proto_ver in [3, 4, 5]:
            if username:
                connect_packet = mqtt_packets.gen_connect("connect-test-%d" % (proto_ver), proto_ver=proto_ver, username="user", password="password")
            else:
                connect_packet = mqtt_packets.gen_connect("connect-test-%d" % (proto_ver), proto_ver=proto_ver)

            if proto_ver == 5:
                if expect_success == True:
                    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
                else:
                    connack_packet = mqtt_packets.gen_connack(rc=mqtt5_rc.NOT_AUTHORIZED, proto_ver=proto_ver, properties=None)
            else:
                if expect_success == True:
                    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
                else:
                    connack_packet = mqtt_packets.gen_connack(rc=5, proto_ver=proto_ver)


            sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
            sock.close()


do_test(allow_anonymous=True,  password_file=True,  username=True,  expect_success=True)
do_test(allow_anonymous=True,  password_file=True,  username=False, expect_success=True)
do_test(allow_anonymous=True,  password_file=False, username=True,  expect_success=True)
do_test(allow_anonymous=True,  password_file=False, username=False, expect_success=True)
do_test(allow_anonymous=False, password_file=True,  username=True,  expect_success=True)
do_test(allow_anonymous=False, password_file=True,  username=False, expect_success=False)
do_test(allow_anonymous=False, password_file=False, username=True,  expect_success=False)
do_test(allow_anonymous=False, password_file=False, username=False, expect_success=False)
