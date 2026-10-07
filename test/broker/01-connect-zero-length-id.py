#!/usr/bin/env python3

# Test whether a CONNECT with a zero length client id results in the correct behaviour.

# MQTT v3.1.1 - zero length is allowed, unless allow_zero_length_clientid is false, and unless clean_start is False.
# MQTT v5.0 - zero length is allowed, unless allow_zero_length_clientid is false

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

def do_test(per_listener, proto_ver, clean_start, allow_zero, client_port, expect_fail):
    connect_packet = mqtt_packets.gen_connect("", proto_ver=proto_ver, clean_session=clean_start)
    if proto_ver == 4:
        if expect_fail == True:
            connack_packet = mqtt_packets.gen_connack(rc=2, proto_ver=proto_ver)
        else:
            connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
    else:
        if expect_fail == True:
            connack_packet = mqtt_packets.gen_connack(rc=128, proto_ver=proto_ver, properties=None)
        else:
            props = mqtt5_props.gen_string_prop(mqtt5_props.ASSIGNED_CLIENT_IDENTIFIER, "auto-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
            connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver, properties=props)
            # Remove the "xxxx" part - this means the front part of the packet
            # is correct (so remaining length etc. is correct), but we don't
            # need to match against the random id.
            connack_packet = connack_packet[:-44]

    broker_config = BrokerConfig(
        listeners=[
            ListenerConfig(
                port=port2,
                allow_anonymous=True,
                allow_zero_length_clientid=allow_zero
            ),
            ListenerConfig(
                port=port1,
                allow_anonymous=True,
                allow_zero_length_clientid=allow_zero
            ),
        ],
        allow_anonymous=True,
        per_listener_settings=per_listener,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=client_port)
        sock.close()


(port1, port2) = mosq_test.get_port(2)

test_v4 = True
test_v5 = True

if test_v4 == True:
    do_test(per_listener=False, proto_ver=4, client_port=port1, clean_start=True, allow_zero=True, expect_fail=False)
    do_test(per_listener=False, proto_ver=4, client_port=port1, clean_start=True, allow_zero=False, expect_fail=True)
    do_test(per_listener=False, proto_ver=4, client_port=port1, clean_start=False, allow_zero=True, expect_fail=True)
    do_test(per_listener=False, proto_ver=4, client_port=port1, clean_start=False, allow_zero=False, expect_fail=True)
    do_test(per_listener=True, proto_ver=4, client_port=port1, clean_start=True, allow_zero=True, expect_fail=False)
    do_test(per_listener=True, proto_ver=4, client_port=port1, clean_start=True, allow_zero=False, expect_fail=True)
    do_test(per_listener=True, proto_ver=4, client_port=port1, clean_start=False, allow_zero=True, expect_fail=True)
    do_test(per_listener=True, proto_ver=4, client_port=port1, clean_start=False, allow_zero=False, expect_fail=True)

    do_test(per_listener=False, proto_ver=4, client_port=port2, clean_start=True, allow_zero=True, expect_fail=False)
    do_test(per_listener=False, proto_ver=4, client_port=port2, clean_start=True, allow_zero=False, expect_fail=True)
    do_test(per_listener=False, proto_ver=4, client_port=port2, clean_start=False, allow_zero=True, expect_fail=True)
    do_test(per_listener=False, proto_ver=4, client_port=port2, clean_start=False, allow_zero=False, expect_fail=True)
    do_test(per_listener=True, proto_ver=4, client_port=port2, clean_start=True, allow_zero=True, expect_fail=False)
    do_test(per_listener=True, proto_ver=4, client_port=port2, clean_start=True, allow_zero=False, expect_fail=True)
    do_test(per_listener=True, proto_ver=4, client_port=port2, clean_start=False, allow_zero=True, expect_fail=True)
    do_test(per_listener=True, proto_ver=4, client_port=port2, clean_start=False, allow_zero=False, expect_fail=True)

    do_test(per_listener=False, proto_ver=4, client_port=port1, clean_start=True, allow_zero=None, expect_fail=False)
    do_test(per_listener=False, proto_ver=4, client_port=port1, clean_start=False, allow_zero=None, expect_fail=True)
    do_test(per_listener=True, proto_ver=4, client_port=port1, clean_start=True, allow_zero=None, expect_fail=False)
    do_test(per_listener=True, proto_ver=4, client_port=port1, clean_start=False, allow_zero=None, expect_fail=True)

    do_test(per_listener=False, proto_ver=4, client_port=port2, clean_start=True, allow_zero=None, expect_fail=False)
    do_test(per_listener=False, proto_ver=4, client_port=port2, clean_start=False, allow_zero=None, expect_fail=True)
    do_test(per_listener=True, proto_ver=4, client_port=port2, clean_start=True, allow_zero=None, expect_fail=False)
    do_test(per_listener=True, proto_ver=4, client_port=port2, clean_start=False, allow_zero=None, expect_fail=True)

if test_v5 == True:
    do_test(per_listener=False, proto_ver=5, client_port=port1, clean_start=True, allow_zero=True, expect_fail=False)
    do_test(per_listener=False, proto_ver=5, client_port=port1, clean_start=True, allow_zero=False, expect_fail=True)
    do_test(per_listener=False, proto_ver=5, client_port=port1, clean_start=False, allow_zero=True, expect_fail=False)
    do_test(per_listener=False, proto_ver=5, client_port=port1, clean_start=False, allow_zero=False, expect_fail=True)
    do_test(per_listener=True, proto_ver=5, client_port=port1, clean_start=True, allow_zero=True, expect_fail=False)
    do_test(per_listener=True, proto_ver=5, client_port=port1, clean_start=True, allow_zero=False, expect_fail=True)
    do_test(per_listener=True, proto_ver=5, client_port=port1, clean_start=False, allow_zero=True, expect_fail=False)
    do_test(per_listener=True, proto_ver=5, client_port=port1, clean_start=False, allow_zero=False, expect_fail=True)

    do_test(per_listener=False, proto_ver=5, client_port=port2, clean_start=True, allow_zero=True, expect_fail=False)
    do_test(per_listener=False, proto_ver=5, client_port=port2, clean_start=True, allow_zero=False, expect_fail=True)
    do_test(per_listener=False, proto_ver=5, client_port=port2, clean_start=False, allow_zero=True, expect_fail=False)
    do_test(per_listener=False, proto_ver=5, client_port=port2, clean_start=False, allow_zero=False, expect_fail=True)
    do_test(per_listener=True, proto_ver=5, client_port=port2, clean_start=True, allow_zero=True, expect_fail=False)
    do_test(per_listener=True, proto_ver=5, client_port=port2, clean_start=True, allow_zero=False, expect_fail=True)
    do_test(per_listener=True, proto_ver=5, client_port=port2, clean_start=False, allow_zero=True, expect_fail=False)
    do_test(per_listener=True, proto_ver=5, client_port=port2, clean_start=False, allow_zero=False, expect_fail=True)

    do_test(per_listener=False, proto_ver=5, client_port=port1, clean_start=True, allow_zero=None, expect_fail=False)
    do_test(per_listener=False, proto_ver=5, client_port=port1, clean_start=False, allow_zero=None, expect_fail=False)
    do_test(per_listener=True, proto_ver=5, client_port=port1, clean_start=True, allow_zero=None, expect_fail=False)
    do_test(per_listener=True, proto_ver=5, client_port=port1, clean_start=False, allow_zero=None, expect_fail=False)

    do_test(per_listener=False, proto_ver=5, client_port=port2, clean_start=True, allow_zero=None, expect_fail=False)
    do_test(per_listener=False, proto_ver=5, client_port=port2, clean_start=False, allow_zero=None, expect_fail=False)
    do_test(per_listener=True, proto_ver=5, client_port=port2, clean_start=True, allow_zero=None, expect_fail=False)
    do_test(per_listener=True, proto_ver=5, client_port=port2, clean_start=False, allow_zero=None, expect_fail=False)
