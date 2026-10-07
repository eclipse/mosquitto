#!/usr/bin/env python3

# Test whether global_max_clients works

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

def do_test():
    connect_packets_ok = []
    connack_packets_ok = []
    connect_props = mqtt5_props.gen_uint32_prop(mqtt5_props.SESSION_EXPIRY_INTERVAL, 60)
    for i in range(0, 10):
        connect_packets_ok.append(mqtt_packets.gen_connect("max-conn-%d"%i, proto_ver=5, properties=connect_props))
        connack_packets_ok.append(mqtt_packets.gen_connack(rc=0, proto_ver=5))

    connect_packet_bad = mqtt_packets.gen_connect("max-conn-bad", proto_ver=5)
    connack_packet_bad = mqtt_packets.gen_connack(rc=mqtt5_rc.SERVER_BUSY, proto_ver=5, property_helper=False)

    socks = []

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        allow_anonymous=True,
        global_max_clients=10,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        # Open all allowed connections, a limit of 10
        for i in range(0, 10):
            socks.append(mosq_test.do_client_connect(connect_packets_ok[i], connack_packets_ok[i], port=port))

        # Try to open an 11th connection
        try:
            sock_bad = mosq_test.do_client_connect(connect_packet_bad, connack_packet_bad, port=port)
        except (ConnectionResetError, BrokenPipeError):
            # Expected behaviour
            pass

        # Close all allowed connections
        for i in range(0, 10):
            socks[i].close()

        ## Session expiry means those clients sessions are still active

        # Try to open an 11th connection
        try:
            sock_bad = mosq_test.do_client_connect(connect_packet_bad, connack_packet_bad, port=port)
        except (ConnectionResetError, BrokenPipeError):
            # Expected behaviour
            pass

do_test()
