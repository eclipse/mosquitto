#!/usr/bin/env python3

from mosq_test_helper import *
from proxy_v2_helper import *
import json
import shutil
import socket

def write_config(filename, port, extra_options):
    with open(filename, 'w') as f:
        f.write("log_type all\n")
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("enable_proxy_protocol_v2 true\n")
        f.write(extra_options)

def do_test(extra_options, expect_fail_log):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')

    rc = 1
    write_config(conf_file, port, extra_options)
    try:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port, expect_fail=True, expect_fail_log=expect_fail_log)
        rc = 0
    except subprocess.TimeoutExpired:
        pass

    os.remove(conf_file)
    if rc != 0:
        raise ValueError(rc)

do_test("use_subject_as_username true\n", "Error: use_subject_as_username cannot be used with enable_proxy_protocol_v2.")
do_test(f"certfile {ssl_dir}/server.crt\nkeyfile {ssl_dir}/server.key\n", "Error: certfile and keyfile cannot be used with enable_proxy_protocol_v2.")
