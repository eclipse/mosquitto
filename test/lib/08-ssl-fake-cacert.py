#!/usr/bin/env python3

from mosq_test_helper import *

mosq_test.require_features(["WITH_TLS"])

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

def do_test(client_cmd):
    port = mosq_test.get_port()

    ssock = mosq_test.listen_sock(port, f"{ssl_dir}/all-ca.crt", f"{ssl_dir}/server.crt", f"{ssl_dir}/server.key", True)

    client_args = [Path(mosq_test.get_build_root(), "test", "lib") / client_cmd, str(port)]
    client = mosq_test.start_client(filename=str(client_cmd).replace('/', '-'), cmd=client_args)

    try:
        (conn, address) = ssock.accept()

        conn.close()
    except ssl.SSLError:
        # Expected error due to ca certs not matching.
        pass
    except mosq_test.TestError:
        pass
    finally:
        time.sleep(1.0)
        if mosq_test.wait_for_subprocess(client):
            print("test client not finished")
            rc=1
        ssock.close()

    if client.returncode == 0:
        exit(0)
    else:
        exit(1)

do_test(Path("c", mosq_test.get_build_type(), "08-ssl-fake-cacert.exe"))
if mosq_test.check_features(["WITH_LIB_CPP"]):
    do_test(Path("cpp", mosq_test.get_build_type(), "08-ssl-fake-cacert.exe"))
