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

def do_test(fam):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    connect_packet = mosq_test.gen_connect("proxy-test", keepalive=42, clean_session=False, proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    rc = 1

    expect_log = "Bad socket read/write on client <unknown>: Invalid input"

    try:
        data = b"a"*501
        sock = do_proxy_v2_connect(port, PROXY_VER, PROXY_CMD_PROXY, fam | PROXY_PROTO_TCP, data)
        try:
            data = sock.recv(10)
            if len(data) == 0:
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
            rc = 1

do_test(PROXY_FAM_IPV4)
do_test(PROXY_FAM_IPV6)
do_test(PROXY_FAM_UNIX)
