#!/usr/bin/env python3

# Test whether a valid CONNECT results in the correct CONNACK packet using an
# SSL connection with client certificates required.

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
        )
    ],
    allow_anonymous=True,
)
broker = MosquittoBroker(config=broker_config)
rc = 1
ssl_eof = False
with broker:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{ssl_dir}/test-root-ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=f"{ssl_dir}/client-expired.crt", keyfile=f"{ssl_dir}/client-expired.key")
    with socket.create_connection(("localhost", port1)) as sock:
        ssock = context.wrap_socket(sock, server_hostname="localhost", suppress_ragged_eofs=True)
        ssock.settimeout(None)
        try:
            ssock.read(1)
        except ssl.SSLEOFError:
            # Under load, sometimes the broker closes the connection after the
            # handshake has failed, but before we have chance to send our
            # payload and so we get an EOF.
            ssl_eof = True
        except ssl.SSLError as err:
            if err.reason == "SSLV3_ALERT_CERTIFICATE_EXPIRED":
                rc = 0
            elif err.errno == 8 and "EOF occurred" in err.strerror:
                rc = 0
            else:
                print(err.strerror)
                raise ValueError(err.errno) from err

if ssl_eof:
    if "certificate verify failed" in stde.decode('utf-8'):
        rc = 0
if rc:
    print(mosq_test.broker_log(broker))

exit(rc)
