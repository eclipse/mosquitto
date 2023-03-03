#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(client):
    port = mosq_test.get_port()

    rc = 1

    client_args = [client, str(port)]
    client = mosq_test.start_client(filename=client.replace('/', '-'), cmd=client_args)

    if mosq_test.wait_for_subprocess(client):
        print("test client not finished")
        rc=1
    else:
        rc=client.returncode
    if rc:
        print(f"Fail: {client}")
        exit(rc)

do_test("c/09-util-topic-tokenise.test")
do_test("cpp/09-util-topic-tokenise.test")
