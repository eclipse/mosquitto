#!/usr/bin/env python3

# Client connects without a certificate to a server that has use_identity_as_username=true. Should be rejected.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_TLS"])

connect_packet = mqtt_packets.gen_connect("connect-no-identity-test")
connack_packet = mqtt_packets.gen_connack(rc=4)

port1 = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners = [
        ListenerConfig(
            port=port1,
            cafile=ssl_dir/'all-ca.crt',
            certfile=ssl_dir/'server.crt',
            keyfile=ssl_dir/'server.key',
            use_identity_as_username=True,
        )
    ],
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{ssl_dir}/test-root-ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssock = context.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    ssock.connect(("localhost", port1))

    mosq_test.do_send_receive(ssock, connect_packet, connack_packet, "connack")
