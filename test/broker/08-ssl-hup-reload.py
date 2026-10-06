#!/usr/bin/env python3

# Test that SIGHUP reloads crlfile, including the removal of a revocation.
#
# The listener points at a private copy of a CRL that the test rewrites in
# place. It starts as crl.pem, which revokes client-revoked.crt, and is then
# replaced by crl-empty.pem, which revokes nothing.
#
# Reloading has to replace the CRL set rather than extend it, so once the
# revocation is gone the previously revoked client has to be accepted again,
# and reinstating it has to take effect too. A valid client must keep working
# across every reload.

from mosq_test_helper import *
from broker_config import BrokerConfig, ListenerConfig
import shutil

mosq_test.require_features(["WITH_TLS"])


def try_connect(port, cert, key, client_id):
    """Attempt a TLS handshake and MQTT CONNECT with the given client cert.

    Returns None if the broker accepted the client, otherwise a short
    description of how it refused.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                         cafile=str(ssl_dir / "test-root-ca.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(ssl_dir / cert),
                            keyfile=str(ssl_dir / key))
    ssock = context.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    try:
        ssock.connect(("localhost", port))
        mosq_test.do_send_receive(ssock, mqtt_packets.gen_connect(client_id),
                                  mqtt_packets.gen_connack(rc=0), "connack")
        return None
    except (ssl.SSLError, BrokenPipeError, ConnectionResetError) as err:
        return f"{type(err).__name__}: {err}"
    finally:
        ssock.close()


def expect_accepted(port, cert, key, client_id, when):
    reason = try_connect(port, cert, key, client_id)
    if reason is not None:
        raise mosq_test.TestError(f"{cert} was refused {when}: {reason}")


def expect_refused(port, cert, key, client_id, when):
    if try_connect(port, cert, key, client_id) is None:
        raise mosq_test.TestError(f"{cert} was accepted {when}")


def set_crlfile(path, source):
    """Atomically replace the listener's crlfile with the contents of source."""
    tmp = path + ".new"
    shutil.copyfile(str(source), tmp)
    os.replace(tmp, path)


crlfile = os.path.basename(__file__).replace('.py', '.crl.pem')
set_crlfile(crlfile, ssl_dir / "crl.pem")

port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners=[
        ListenerConfig(
            port=port,
            cafile=ssl_dir / "all-ca.crt",
            certfile=ssl_dir / "server.crt",
            keyfile=ssl_dir / "server.key",
            require_certificate=True,
            crlfile=crlfile,
        ),
    ],
    allow_anonymous=True,
)

with MosquittoBroker(config=broker_config) as broker:
    broker.add_extra_file(crlfile)

    expect_accepted(port, "client.crt", "client.key", "hup-valid-0", "before any reload")
    expect_refused(port, "client-revoked.crt", "client-revoked.key", "hup-revoked-0",
                   "before any reload, while it is still revoked")

    # Alternate between revoking and un-revoking, so that each reload has to
    # both add and drop a revocation, and repeated reloads are exercised.
    for i in range(2):
        set_crlfile(crlfile, ssl_dir / "crl-empty.pem")
        broker.reload()
        time.sleep(1)
        expect_accepted(port, "client.crt", "client.key", f"hup-valid-empty-{i}",
                        f"after crlfile was emptied (round {i})")
        expect_accepted(port, "client-revoked.crt", "client-revoked.key", f"hup-revoked-empty-{i}",
                        f"after its revocation was removed from crlfile (round {i})")

        set_crlfile(crlfile, ssl_dir / "crl.pem")
        broker.reload()
        time.sleep(1)
        expect_accepted(port, "client.crt", "client.key", f"hup-valid-crl-{i}",
                        f"after crlfile was reinstated (round {i})")
        expect_refused(port, "client-revoked.crt", "client-revoked.key", f"hup-revoked-crl-{i}",
                       f"after its revocation was reinstated in crlfile (round {i})")

    if not broker.is_running():
        raise mosq_test.TestError("Broker is no longer running after the certificate reloads")
