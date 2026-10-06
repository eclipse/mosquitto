#!/usr/bin/env python3

# Test that SIGHUP reloads cafile and capath so that CA cert rotations take
# effect.
#
# The listener points at a private copy of a CA bundle or directory that the
# test rewrites in place. It starts with the CA chain that signed client.crt,
# is then replaced by an unrelated CA, and is finally restored.
#
# Reloading has to replace the trust store rather than extend it, so after the
# rotation client.crt must be refused, and after the restore it must be
# accepted again.

from mosq_test_helper import *
from broker_config import BrokerConfig, ListenerConfig
import shutil
import subprocess

mosq_test.require_features(["WITH_TLS"])


def try_connect(port, client_id):
    """Attempt a TLS handshake and MQTT CONNECT using client.crt.

    Returns None if the broker accepted the client, otherwise a short
    description of how it refused.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                         cafile=str(ssl_dir / "test-root-ca.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(ssl_dir / "client.crt"),
                            keyfile=str(ssl_dir / "client.key"))
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


def expect_accepted(port, client_id, when):
    reason = try_connect(port, client_id)
    if reason is not None:
        raise mosq_test.TestError(f"client.crt was refused {when}: {reason}")


def expect_refused(port, client_id, when):
    if try_connect(port, client_id) is None:
        raise mosq_test.TestError(f"client.crt was accepted {when}")


def subject_hash(cert):
    result = subprocess.run(['openssl', 'x509', '-hash', '-noout', '-in', str(cert)],
                            capture_output=True, timeout=10)
    if result.returncode != 0:
        raise mosq_test.TestError(
            f"openssl could not hash {cert}: {result.stderr.decode()}")
    return result.stdout.decode().strip()


def set_cafile(path, source):
    """Atomically replace the listener's cafile with the contents of source."""
    tmp = path + ".new"
    shutil.copyfile(source, tmp)
    os.replace(tmp, path)


def set_capath(path, ca_names):
    """Replace the contents of the capath directory with the given CA certs."""
    for entry in os.listdir(path):
        os.remove(os.path.join(path, entry))
    for name in ca_names:
        source = ssl_dir / name
        shutil.copyfile(source, os.path.join(path, f"{subject_hash(source)}.0"))


def run_rotation_test(trust_store, trusted_cas, unrelated_cas):
    is_cafile = trust_store == "cafile"
    store_path = os.path.basename(__file__).replace(
        '.py', f'.{trust_store}')

    if is_cafile:
        set_cafile(store_path, ssl_dir / trusted_cas[0])
    else:
        shutil.rmtree(store_path, ignore_errors=True)
        os.mkdir(store_path)
        set_capath(store_path, trusted_cas)

    port = mosq_test.get_port()
    listener_args = {
        "port": port,
        "certfile": ssl_dir / "server.crt",
        "keyfile": ssl_dir / "server.key",
        "require_certificate": True,
    }
    listener_args["cafile" if is_cafile else "capath"] = store_path
    broker_config = BrokerConfig(
        listeners=[ListenerConfig(**listener_args)],
        allow_anonymous=True,
    )

    with MosquittoBroker(config=broker_config) as broker:
        if is_cafile:
            broker.add_extra_file(store_path)

        prefix = trust_store + "-rotation"
        expect_accepted(port, f"{prefix}-before", "before any reload")

        if is_cafile:
            set_cafile(store_path, ssl_dir / unrelated_cas[0])
        else:
            set_capath(store_path, unrelated_cas)
        broker.reload()
        time.sleep(1)
        expect_refused(port, f"{prefix}-rotated",
                       f"after {trust_store} was rotated to an unrelated CA")

        if is_cafile:
            set_cafile(store_path, ssl_dir / trusted_cas[0])
        else:
            set_capath(store_path, trusted_cas)
        broker.reload()
        time.sleep(1)
        expect_accepted(port, f"{prefix}-restored",
                        f"after the original {trust_store} was restored")

        if not broker.is_running():
            raise mosq_test.TestError(
                "Broker is no longer running after the certificate reloads")

    if not is_cafile:
        shutil.rmtree(store_path, ignore_errors=True)


if shutil.which("openssl") is None:
    print("openssl command not available, skipping")
    sys.exit(77)

UNRELATED_CAS = ["test-fake-root-ca.crt"]

# Run the test for a hierarchy of CA certs in a single file
run_rotation_test("cafile", ["all-ca.crt"], UNRELATED_CAS)

# Run the test for a hierarchy of CA certs in a directory of individual files
TRUSTED_CAS = ["test-root-ca.crt", "test-signing-ca.crt"]
run_rotation_test("capath", TRUSTED_CAS, UNRELATED_CAS)
