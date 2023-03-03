#!/usr/bin/env python3

from mosq_test_helper import *

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

def do_test(client_cmd):
    rc = 1

    port = mosq_test.get_port()

    client_args = [mosq_test.get_build_root() + "/test/lib/" + client_cmd, str(port)]
    client = mosq_test.start_client(filename=client_cmd.replace('/', '-'), cmd=client_args)

    if mosq_test.wait_for_subprocess(client):
        print("test client not finished")
        rc=1
    else:
        rc=client.returncode

    if rc:
        (o, e) = client.communicate()
        print(o)
        print(e)
        exit(rc)

do_test("c/08-ssl-bad-cacert.test")
do_test("cpp/08-ssl-bad-cacert.test")
