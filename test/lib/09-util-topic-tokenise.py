#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(client):
    port = mosq_test.get_port()

    rc = 1

    client_args = [client, str(port)]
    client = mosq_test.start_client(filename=str(client).replace('/', '-'), cmd=client_args)

    if mosq_test.wait_for_subprocess(client):
        print("test client not finished")
        rc=1
    else:
        rc=client.returncode
    if rc:
        print(f"Fail: {client}")
        exit(rc)

do_test(Path("c", mosq_test.get_build_type(), "09-util-topic-tokenise.exe"))
if mosq_test.check_features(["WITH_LIB_CPP"]):
    do_test(Path("cpp", mosq_test.get_build_type(), "09-util-topic-tokenise.exe"))
