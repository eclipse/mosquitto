#!/usr/bin/env python3

# Test that the TLS certificate chain is stable and correct across SIGHUP reloads.
#
# Reloading recreates the listener's SSL_CTX, so this guards against the served
# chain being lost, truncated or duplicated in the process.
#
# A certfile containing both the leaf certificate and an intermediate signing
# CA is configured. After each SIGHUP the test connects via openssl s_client
# and extracts the SHA-256 fingerprint of every certificate in the server's
# chain, verifying that:
#   1. Exactly 2 certificates are presented (leaf + intermediate).
#   2. The leaf is always server.crt.
#   3. The intermediate is always test-signing-ca.crt (no stale or duplicate
#      entries).

from mosq_test_helper import *
from broker_config import BrokerConfig, ListenerConfig
import hashlib
import re
import shutil
import subprocess

mosq_test.require_features(["WITH_TLS"])

if shutil.which("openssl") is None:
    print("openssl command not available, skipping")
    sys.exit(77)

SIGHUP_COUNT = 3


def pem_to_fingerprint(pem_path):
    """Return the SHA-256 fingerprint (hex) of the first certificate in a PEM file.
    Handles both plain PEM and OpenSSL text+PEM combined format."""
    text = open(pem_path).read()
    match = re.search(
        r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----',
        text, re.DOTALL)
    if not match:
        raise ValueError(f"No PEM certificate block found in {pem_path}")
    der = ssl.PEM_cert_to_DER_cert(match.group(0))
    return hashlib.sha256(der).hexdigest()


def get_chain_fingerprints(port, ca_file, client_cert, client_key):
    """Connect via openssl s_client with -showcerts and return the SHA-256
    fingerprint of every certificate in the server's chain (leaf first)."""
    try:
        result = subprocess.run(
            ['openssl', 's_client',
             '-connect', f'localhost:{port}',
             '-CAfile', str(ca_file),
             '-cert', str(client_cert),
             '-key', str(client_key),
             '-servername', 'localhost',
             '-showcerts'],
            input=b'',
            capture_output=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        raise mosq_test.TestError(
            f"openssl s_client timed out connecting to localhost:{port}")

    output = result.stdout.decode()
    pem_blocks = re.findall(
        r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----',
        output, re.DOTALL)
    if not pem_blocks:
        raise mosq_test.TestError(
            "openssl s_client returned no certificates:\n"
            f"{result.stderr.decode()}")
    return [hashlib.sha256(ssl.PEM_cert_to_DER_cert(p)).hexdigest()
            for p in pem_blocks]


def connect_valid(port):
    """Connect with a valid client certificate; expect CONNACK rc=0."""
    connect_packet = mqtt_packets.gen_connect("chain-hup-valid")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                         cafile=str(ssl_dir / "test-root-ca.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(ssl_dir / "client.crt"),
                            keyfile=str(ssl_dir / "client.key"))
    ssock = context.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    ssock.connect(("localhost", port))
    mosq_test.do_send_receive(ssock, connect_packet, connack_packet, "connack")
    ssock.close()


# Pre-compute expected fingerprints from the source PEM files.
fp_leaf         = pem_to_fingerprint(str(ssl_dir / "server.crt"))
fp_intermediate = pem_to_fingerprint(str(ssl_dir / "test-signing-ca.crt"))
expected_chain  = [fp_leaf, fp_intermediate]

port = mosq_test.get_port()

# Build a chain certfile (leaf + intermediate signing CA) in the cwd so
# we don't modify the shared ssl/ fixtures.
chain_certfile = os.path.basename(__file__).replace('.py', '.server-chain.crt')
with open(chain_certfile, 'w') as out:
    out.write(open(str(ssl_dir / "server.crt")).read())
    out.write(open(str(ssl_dir / "test-signing-ca.crt")).read())

broker_config = BrokerConfig(
    listeners=[
        ListenerConfig(
            port=port,
            cafile=ssl_dir / "all-ca.crt",
            certfile=chain_certfile,
            keyfile=ssl_dir / "server.key",
            require_certificate=True,
            crlfile=ssl_dir / "crl.pem",
        ),
    ],
    allow_anonymous=True,
)

with MosquittoBroker(config=broker_config) as broker:
    broker.add_extra_file(chain_certfile)

    # Baseline check before any reload.
    chain = get_chain_fingerprints(port,
                                   str(ssl_dir / "test-root-ca.crt"),
                                   str(ssl_dir / "client.crt"),
                                   str(ssl_dir / "client.key"))
    if chain != expected_chain:
        raise mosq_test.TestError(
            f"Baseline chain fingerprints mismatch\n"
            f"  got:      {chain}\n"
            f"  expected: {expected_chain}")

    for i in range(SIGHUP_COUNT):
        broker.reload()
        time.sleep(1)

        connect_valid(port)

        chain = get_chain_fingerprints(port,
                                       str(ssl_dir / "test-root-ca.crt"),
                                       str(ssl_dir / "client.crt"),
                                       str(ssl_dir / "client.key"))
        if chain != expected_chain:
            raise mosq_test.TestError(
                f"After SIGHUP #{i+1}: chain fingerprints mismatch\n"
                f"  got:      {chain}\n"
                f"  expected: {expected_chain}")

    if not broker.is_running():
        raise mosq_test.TestError("Broker is no longer running after the certificate reloads")
