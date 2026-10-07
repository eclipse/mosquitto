#!/usr/bin/env python3

# Test whether max_connections works with repeated connections

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker


def test_iteration(port, connect_packets_ok, connack_packets_ok, connect_packet_bad, connack_packet_bad):
    socks = []

    # Open all allowed connections, a limit of 10
    for i in range(0, 10):
        socks.append(mosq_test.do_client_connect(connect_packets_ok[i], connack_packets_ok[i], port=port))

    # Try to open an 11th connection
    try:
        sock_bad = mosq_test.do_client_connect(connect_packet_bad, connack_packet_bad, port=port)
    except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
        # Expected behaviour
        pass
    except OSError as e:
        if e.errno == errno.ENOTCONN:
            pass
        else:
            raise e

    # Close all allowed connections
    for i in range(0, 10):
        socks[i].close()


def do_test():
    connect_packets_ok = []
    connack_packets_ok = []
    for i in range(0, 10):
        connect_packets_ok.append(mqtt_packets.gen_connect("max-conn-%d"%i, proto_ver=5))
        connack_packets_ok.append(mqtt_packets.gen_connack(rc=0, proto_ver=5))

    connect_packet_bad = mqtt_packets.gen_connect("max-conn-bad", proto_ver=5)
    connack_packet_bad = b""

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        allow_anonymous=True,
        max_connections=10,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        test_iteration(port, connect_packets_ok, connack_packets_ok, connect_packet_bad, connack_packet_bad)

        ## Now repeat - check it works as before

        if os.environ.get('MOSQ_USE_VALGRIND') is not None:
            time.sleep(0.5)

        test_iteration(port, connect_packets_ok, connack_packets_ok, connect_packet_bad, connack_packet_bad)

do_test()
