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
        f.write("enable_proxy_protocol 1\n")

def do_test(data, expect_log):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    connect_packet = mosq_test.gen_connect("proxy-test", keepalive=42, clean_session=False, proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    rc = 1

    try:
        sock = do_proxy_v1_connect(port, data)
        try:
            d = sock.recv(1)
            if len(d) == 0:
                rc = 0
        except ConnectionResetError:
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
            print(data)
            exit(1)


# Basic
do_test(b"PROXY TCP3 192.0.2.5 127.0.0.1 6275 1234\r\n", "Connection rejected, corrupt PROXY header.") # Bad transport
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1234                                                                   \r\n", "Connection rejected, corrupt PROXY header.") # Too long

# TCP4
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 6275\r\n", "Connection rejected, corrupt PROXY header.") # Missing dport
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1\r\n", "Connection rejected, corrupt PROXY header.") # Missing sport
do_test(b"PROXY TCP4 192.0.2.5\r\n", "Connection rejected, corrupt PROXY header.") # Missing daddr
do_test(b"PROXY TCP4 \r\n", "Connection rejected, corrupt PROXY header.") # Missing saddr
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 0\r\n", "Connection rejected, corrupt PROXY header.") # dport == 0
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 65536\r\n", "Connection rejected, corrupt PROXY header.") # dport == 65536
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 0 1234\r\n", "Connection rejected, corrupt PROXY header.") # sport == 0
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 65536 1234\r\n", "Connection rejected, corrupt PROXY header.") # sport == 65536
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.256 6275 1234\r\n", "Connection rejected, corrupt PROXY header.") # daddr invalid
do_test(b"PROXY TCP4 192.0.2.256 127.0.0.1 6275 1234\r\n", "Connection rejected, corrupt PROXY header.") # saddr invalid

# TCP6
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.1 6275\r\n", "Connection rejected, corrupt PROXY header.") # Missing dport
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.1\r\n", "Connection rejected, corrupt PROXY header.") # Missing sport
do_test(b"PROXY TCP6 192.0.2.5\r\n", "Connection rejected, corrupt PROXY header.") # Missing daddr
do_test(b"PROXY TCP6 \r\n", "Connection rejected, corrupt PROXY header.") # Missing saddr
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.1 6275 0\r\n", "Connection rejected, corrupt PROXY header.") # dport == 0
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.1 6275 65536\r\n", "Connection rejected, corrupt PROXY header.") # dport == 65536
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.1 0 1234\r\n", "Connection rejected, corrupt PROXY header.") # sport == 0
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.1 65536 1234\r\n", "Connection rejected, corrupt PROXY header.") # sport == 65536
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.256 6275 1234\r\n", "Connection rejected, corrupt PROXY header.") # daddr invalid
do_test(b"PROXY TCP6 192.0.2.256 127.0.0.1 6275 1234\r\n", "Connection rejected, corrupt PROXY header.") # saddr invalid
