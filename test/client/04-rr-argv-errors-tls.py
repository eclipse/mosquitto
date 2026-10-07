#!/usr/bin/env python3

#

from mosq_test_helper import *

mosq_test.require_features(["WITH_TLS"])

def do_test(args, stderr_expected, rc_expected):
    client_run(mosq_paths.mosquitto_rr, args, stderr_expected, rc_expected)


if __name__ == '__main__':
    # Missing args for TLS related options
    do_test(['--cafile'], "Error: --cafile argument given but no file specified.", 1)
    do_test(['--capath'], "Error: --capath argument given but no directory specified.", 1)
    do_test(['--cert'], "Error: --cert argument given but no file specified.", 1)
    do_test(['--ciphers'], "Error: --ciphers argument given but no ciphers specified.", 1)
    do_test(['--key'], "Error: --key argument given but no file specified.", 1)
    do_test(['--keyform'], "Error: --keyform argument given but no keyform specified.", 1)
    do_test(['--tls-alpn'], "Error: --tls-alpn argument given but no protocol specified.", 1)
    do_test(['--tls-engine'], "Error: --tls-engine argument given but no engine_id specified.", 1)
    do_test(['--tls-engine-kpass-sha1'], "Error: --tls-engine-kpass-sha1 argument given but no kpass sha1 specified.", 1)
    do_test(['--tls-version'], "Error: --tls-version argument given but no version specified.", 1)
