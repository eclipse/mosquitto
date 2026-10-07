#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_TLS"])

port1 = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners = [
        ListenerConfig(
            port=port1,
            cafile=ssl_dir/'all-ca.crt',
            certfile=ssl_dir/'server.crt',
            keyfile=ssl_dir/'server.key',
            require_certificate=True,
            crlfile=ssl_dir/'crl.pem',
        )
    ],
    allow_anonymous=True,
)
broker = MosquittoBroker(config=broker_config)
ssl_eof = False
rc = 1

with broker:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{ssl_dir}/test-root-ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=f"{ssl_dir}/client-revoked.crt", keyfile=f"{ssl_dir}/client-revoked.key")
    ssock = context.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    try:
        ssock.connect(("localhost", port1))
        try:
            ssock.read(1)
        except ssl.SSLEOFError:
            # Under load, sometimes the broker closes the connection after the
            # handshake has failed, but before we have chance to send our
            # payload and so we get an EOF.
            ssl_eof = True
        except ssl.SSLError as err:
            if err.reason == "SSLV3_ALERT_CERTIFICATE_REVOKED":
                rc = 0
            elif err.errno == 8 and "EOF occurred" in err.strerror:
                rc = 0
            else:
                mosq_test.terminate_broker(broker)
                print(err.strerror)
                raise ValueError(err.errno) from err
    except ssl.SSLError as err:
        if err.errno == 1 and "certificate revoked" in err.strerror:
            rc = 0
        elif err.errno == 8 and "EOF occurred" in err.strerror:
            rc = 0
        else:
            print(err.strerror)
            raise ValueError(err.errno)

if ssl_eof:
    if "certificate verify failed" in stde.decode('utf-8'):
        rc = 0
if rc:
    print(broker.get_log())
exit(rc)
