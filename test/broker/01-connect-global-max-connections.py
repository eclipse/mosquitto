#!/usr/bin/env python3

# Test whether global_max_connections works

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker


def do_test():
    connect_packets_ok = []
    connack_packets_ok = []
    for i in range(0, 10):
        connect_packets_ok.append(mqtt_packets.gen_connect("max-conn-%d"%i, proto_ver=5))
        connack_packets_ok.append(mqtt_packets.gen_connack(rc=0, proto_ver=5))

    connect_packet_bad = mqtt_packets.gen_connect("max-conn-bad", proto_ver=5)
    connack_packet_bad = b""

    socks = []

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        allow_anonymous=True,
        global_max_connections=10,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        # Open all allowed connections, a limit of 10
        for i in range(0, 10):
            socks.append(mosq_test.do_client_connect(connect_packets_ok[i], connack_packets_ok[i], port=port))

        # Try to open an 11th connection
        try:
            mosq_test.do_client_connect(connect_packet_bad, connack_packet_bad, port=port)
            print("did not throw when trying to open 11th connection (first time)")
            return rc
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            # Expected behaviour
            pass
        finally:
            # Close all allowed connections
            for sock in socks:
                sock.close()
            socks.clear()

        ## Now repeat - check it works as before

        if os.environ.get('MOSQ_USE_VALGRIND') is not None:
            time.sleep(0.5)

        # Open all allowed connections, a limit of 10
        for i in range(0, 10):
            socks.append(mosq_test.do_client_connect(connect_packets_ok[i], connack_packets_ok[i], port=port))

        # Try to open an 11th connection
        try:
            mosq_test.do_client_connect(connect_packet_bad, connack_packet_bad, port=port)
            print("did not throw when trying to open 11th connection (second time)")
            return rc
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            # Expected behaviour
            pass
        finally:
            # Close all allowed connections
            for sock in socks:
                sock.close()
            socks.clear()

do_test()
