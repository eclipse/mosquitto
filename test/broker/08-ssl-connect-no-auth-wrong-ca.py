#!/usr/bin/env python3

# Test whether a valid CONNECT results in the correct CONNACK packet using an SSL connection.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

connect_packet = mqtt_packets.gen_connect("connect-success-test")
connack_packet = mqtt_packets.gen_connack(rc=0)

port1 = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners = [
        ListenerConfig(
            port=port1,
            cafile=ssl_dir/'all-ca.crt',
            certfile=ssl_dir/'server.crt',
            keyfile=ssl_dir/'server.key',
        )
    ],
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{ssl_dir}/test-alt-ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssock = context.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    try:
        ssock.connect(("localhost", port1))
    except ssl.SSLError as err:
        if err.errno == 1:
            pass
    finally:
        ssock.close()
