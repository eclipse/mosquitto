#!/usr/bin/env python3

# Test whether a client connected with a client certificate when
# use_identity_as_username is true is then disconnected when a SIGHUP is
# received.
# https://github.com/eclipse-mosquitto/mosquitto/issues/1402

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_TLS"])

def write_pwfile(filename):
    with open(filename, 'w') as f:
        # Username "test client", password test
        f.write('test client:$6$njERlZMi/7DzNB9E$iiavfuXvUm8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==\n')

def do_test(option):
    pw_file = os.path.basename(__file__).replace('.py', '.pwfile')
    write_pwfile(pw_file)

    connect_packet = mqtt_packets.gen_connect("connect-success-test")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [
            ListenerConfig(
                port=port,
                cafile=ssl_dir/"all-ca.crt",
                certfile=ssl_dir/"server.crt",
                keyfile=ssl_dir/"server.key",
                require_certificate=True,
            )
        ],
        password_file=pw_file,
        allow_anonymous=True,
    )
    setattr(broker_config.listeners[0], option, True)
    broker = MosquittoBroker(config=broker_config)
    broker.add_extra_file(pw_file)
    with broker:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{ssl_dir}/test-root-ca.crt")
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=f"{ssl_dir}/client.crt", keyfile=f"{ssl_dir}/client.key")
        ssock = context.wrap_socket(sock, server_hostname="localhost")
        ssock.settimeout(20)
        ssock.connect(("localhost", port))
        mosq_test.do_send_receive(ssock, connect_packet, connack_packet, "connack")

        broker.reload()
        time.sleep(1)

        # This will fail if we've been disconnected
        mosq_test.do_ping(ssock)
        ssock.close()


do_test("use_identity_as_username")
do_test("use_subject_as_username")
