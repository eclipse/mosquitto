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
            exit(1)

do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1234\r\n", "New client connected from 192.0.2.5:6275")
do_test(b"PROXY TCP6 2001:db8:506:708:900::1 ::1 6275 1234\r\n", "New client connected from 2001:db8:506:708:900::1:6275 as proxy-test (p5, c0, k42)")
do_test(b"PROXY UNKNOWN \r\n", "New client connected from 127.0.0.1:")
