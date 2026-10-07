#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

def do_test(port1_prefix, port2_prefix, global_prefix, client_port, auto_id):
    connect_packet = mqtt_packets.gen_connect("", proto_ver=5)
    props = mqtt5_props.gen_string_prop(mqtt5_props.ASSIGNED_CLIENT_IDENTIFIER, f"{auto_id}xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=props)
    # Remove the "xxxx" part - this means the front part of the packet
    # is correct (so remaining length etc. is correct), but we don't
    # need to match against the random id.
    connack_packet = connack_packet[:-44]

    broker_config = BrokerConfig(
        listeners = [
            ListenerConfig(
                port=port2,
                listener_auto_id_prefix=port2_prefix,
            ),
            ListenerConfig(
                port=port1,
                listener_auto_id_prefix=port1_prefix,
            ),
        ],
        allow_anonymous=True,
        auto_id_prefix=global_prefix,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=client_port)
        sock.close()


(port1, port2) = mosq_test.get_port(2)
do_test(port1_prefix=None,     port2_prefix=None,     global_prefix=None,      client_port=port1, auto_id="auto-")
do_test(port1_prefix=None,     port2_prefix=None,     global_prefix=None,      client_port=port2, auto_id="auto-")
do_test(port1_prefix=None,     port2_prefix=None,     global_prefix="new-",    client_port=port1, auto_id="new-")
do_test(port1_prefix=None,     port2_prefix=None,     global_prefix="new-",    client_port=port2, auto_id="new-")
do_test(port1_prefix=None,     port2_prefix="port2-", global_prefix=None,      client_port=port1, auto_id="auto-")
do_test(port1_prefix=None,     port2_prefix="port2-", global_prefix=None,      client_port=port2, auto_id="port2-")
do_test(port1_prefix="port1-", port2_prefix="port2-", global_prefix=None,      client_port=port1, auto_id="port1-")
do_test(port1_prefix="port1-", port2_prefix="port2-", global_prefix=None,      client_port=port2, auto_id="port2-")
do_test(port1_prefix="port1-", port2_prefix="port2-", global_prefix="global-", client_port=port1, auto_id="port1-")
do_test(port1_prefix="port1-", port2_prefix="port2-", global_prefix="global-", client_port=port2, auto_id="port2-")
do_test(port1_prefix="port1-", port2_prefix=None,     global_prefix="global-", client_port=port1, auto_id="port1-")
do_test(port1_prefix="port1-", port2_prefix=None,     global_prefix="global-", client_port=port2, auto_id="global-")
