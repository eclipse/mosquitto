#!/usr/bin/env python3

from mosq_test_helper import *
import json
import shutil
import socket

def write_config(filename, port, ver):
    with open(filename, 'w') as f:
        f.write("log_type all\n")
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write(f"enable_proxy_protocol {ver}\n")

def do_test(ver, expect_fail_log):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')

    rc = 1
    write_config(conf_file, port, ver)
    try:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port, expect_fail=True, expect_fail_log=expect_fail_log)
        rc = 0
    except subprocess.TimeoutExpired:
        pass

    os.remove(conf_file)
    if rc != 0:
        raise ValueError(rc)

do_test(0, "Error: enable_proxy_protocol must be 1 or 2.")
do_test(3, "Error: enable_proxy_protocol must be 1 or 2.")
