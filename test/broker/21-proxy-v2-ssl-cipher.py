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

def do_test(data):
    expect_log = "Connection from 192.0.2.5:6275 negotiated TLSv1.3 cipher pqrstuv"
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    connect_packet = mosq_test.gen_connect("proxy-test", keepalive=42, clean_session=False, proto_ver=5, username="none", password="pw")
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    rc = 1

    try:
        sock = do_proxy_v2_connect(port, PROXY_VER, PROXY_CMD_PROXY, PROXY_FAM_IPV4 | PROXY_PROTO_TCP, data)
        mosq_test.do_send_receive(sock, connect_packet, connack_packet, "connack")
        mosq_test.do_ping(sock)
        sock.close()
        rc = 0
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
            rc = 1
            raise ValueError(rc)

data = b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00" \
    + b"\x20" \
    + b"\x00\x19" \
    + b"\x05" \
    + b"\x00\x00\x00\x00" \
    + b"\x21" \
    + b"\x00\x07" \
    + b"\x54\x4C\x53\x76\x31\x2E\x33" \
    + b"\x23" \
    + b"\x00\x07" \
    + b"\x70\x71\x72\x73\x74\x75\x76"
do_test(data)
