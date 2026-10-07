#!/usr/bin/env python3

# Test whether connections to a unix socket work

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_UNIX_SOCKETS"])

try:
    s = socket.AF_UNIX
except AttributeError:
    # Not supported on Windows
    exit(77)


def do_test():
    connect_packet = mqtt_packets.gen_connect("unix-socket")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    port = mosq_test.get_port()
    sockpath = f"{port}.sock"
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(
            port=0,
            address=sockpath,
        )],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config, check_port=False)
    broker.add_extra_file(sockpath)
    with broker:
        if os.environ.get('MOSQ_USE_VALGRIND') is None:
            time.sleep(0.1)
        else:
            time.sleep(2)
        sock = mosq_test.do_client_connect_unix(connect_packet, connack_packet, path=f"{port}.sock")
        sock.close()

do_test()
