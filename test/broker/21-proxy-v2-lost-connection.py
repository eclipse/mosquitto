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

connect_packet = mosq_test.gen_connect("proxy-test", keepalive=42, clean_session=False, proto_ver=5)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

def do_test(header):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    rc = 1

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("localhost", port))
        sock.send(header)
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
        if rc != 0:
            print(stde.decode('utf-8'))
            rc = 1
            raise ValueError(rc)

# This test essentially should never fail, but it covers a code path that is
# not covered by the other tests and should be used with valgrind/sanitisers

# Not enough data, IPv4
proxy_header = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a" + b"\x21\x11\x00\x0f" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x00\x00"
do_test(proxy_header)
