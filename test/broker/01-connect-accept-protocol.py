#!/usr/bin/env python3

# Test accept_protocol_version option

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

def do_test(accept, expect_success):
    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        accept_protocol_versions=accept,
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        for proto_ver in [3, 4, 5]:
            rc = 1
            connect_packet = mqtt_packets.gen_connect("accept-protocol-test-%d" % (proto_ver), proto_ver=proto_ver)

            if proto_ver == 5:
                if proto_ver in expect_success:
                    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
                else:
                    connack_packet = mqtt_packets.gen_connack(rc=mqtt5_rc.UNSUPPORTED_PROTOCOL_VERSION, proto_ver=proto_ver, properties=None)
            else:
                if proto_ver in expect_success:
                    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
                else:
                    connack_packet = mqtt_packets.gen_connack(rc=1, proto_ver=proto_ver)


            sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
            sock.close()


do_test(accept="3,4,5", expect_success=[3, 4, 5])
do_test(accept="5,4,3", expect_success=[3, 4, 5])
do_test(accept="3 ,4, 5", expect_success=[3, 4, 5])
do_test(accept="    ,   3   ,    4  ,   5    ", expect_success=[3, 4, 5])
do_test(accept="3", expect_success=[3])
do_test(accept="4", expect_success=[4])
do_test(accept="5", expect_success=[5])
do_test(accept="3,4", expect_success=[3, 4])
do_test(accept="3,5", expect_success=[3, 5])
do_test(accept="4,3", expect_success=[3, 4])
do_test(accept="4,5", expect_success=[4, 5])
do_test(accept="5,3", expect_success=[3, 5])
