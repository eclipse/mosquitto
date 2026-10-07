#!/usr/bin/env python3

# Test whether a valid CONNECT results in the correct CONNACK packet using an SSL connection.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_TLS"])

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
            require_certificate=True,
        )
    ],
    allow_anonymous=True,
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{ssl_dir}/test-root-ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=f"{ssl_dir}/client.crt", keyfile=f"{ssl_dir}/client.key")
    ssock = context.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    ssock.connect(("localhost", port1))

    mosq_test.do_send_receive(ssock, connect_packet, connack_packet, "connack")
    ssock.close()
