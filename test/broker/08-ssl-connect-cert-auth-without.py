#!/usr/bin/env python3

# Test whether a client can connect without an SSL certificate if one is required.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_TLS"])

connect_packet = mqtt_packets.gen_connect("connect-cert-test")

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
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssock = context.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    try:
        ssock.connect(("localhost", port1))
        mosq_test.do_send_receive(ssock, connect_packet, "", "connack")
    except ssl.SSLEOFError as err:
        pass
    except ssl.SSLError as err:
        if err.errno == 1:
            pass
        else:
            print("unexpected SSLError occurred", err)
    except socket.error as err:
        if err.errno == errno.ECONNRESET:
            pass
        else:
            print("unexpected socket.error occurred", err)
