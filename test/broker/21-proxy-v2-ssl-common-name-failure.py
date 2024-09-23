#!/usr/bin/env python3

from mosq_test_helper import *
from proxy_helper import *
import json
import shutil
import socket

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("log_type all\n")
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("enable_proxy_protocol 2\n")
        f.write("require_certificate true\n")
        f.write("use_identity_as_username true\n")

def do_test(data, expect_log):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    connect_packet = mosq_test.gen_connect("proxy-test", keepalive=42, clean_session=False, proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=134, proto_ver=5)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    rc = 1

    try:
        sock = do_proxy_v2_connect(port, PROXY_VER, PROXY_CMD_PROXY, PROXY_FAM_IPV4 | PROXY_PROTO_TCP, data)
        sock.send(connect_packet)
        try:
            mosq_test.expect_packet(sock, "connack", connack_packet)
            data = sock.recv(10)
            if len(data) == 0:
                rc = 0
        except (BrokenPipeError, ConnectionResetError):
            rc = 0
        sock.close()
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc != 0 or expect_log not in stde.decode('utf-8'):
            print(stde.decode('utf-8'))
            print(expect_log)
            rc = 1
            raise ValueError(rc)

# No SSL at all
data = b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00"
expect_log = "rejected, client did not provide a certificate."
do_test(data, expect_log)

# SSL but no certificate at all - this should fail
# IP, IP, port, port, SSL-tlv, length, client, verify, SSL-version sub-tlv, length, value
data = b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00" \
    + b"\x20" \
    + b"\x00\x0F" \
    + b"\x01" \
    + b"\x00\x00\x00\x01" \
    + b"\x21" \
    + b"\x00\x07" \
    + b"\x54\x4C\x53\x76\x31\x2E\x33"
expect_log = "rejected, client did not provide a certificate."
do_test(data, expect_log)

# SSL, verify 0 but no certificate presented this session
# IP, IP, port, port, SSL-tlv, length, client, verify, SSL-version sub-tlv, length, value
data = b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00" \
    + b"\x20" \
    + b"\x00\x0F" \
    + b"\x01" \
    + b"\x00\x00\x00\x00" \
    + b"\x21" \
    + b"\x00\x07" \
    + b"\x54\x4C\x53\x76\x31\x2E\x33"
expect_log = "rejected, client did not provide a certificate."
do_test(data, expect_log)

data = b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00" \
    + b"\x20" \
    + b"\x00\x0F" \
    + b"\x05" \
    + b"\x00\x00\x00\x00" \
    + b"\x21" \
    + b"\x00\x07" \
    + b"\x54\x4C\x53\x76\x31\x2E\x33"
expect_log = "Client proxy-test disconnected, not authorised."
do_test(data, expect_log)
