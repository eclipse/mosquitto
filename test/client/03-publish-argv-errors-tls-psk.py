#!/usr/bin/env python3

#

from mosq_test_helper import *

mosq_test.require_features(["WITH_CLIENTS", "WITH_TLS", "WITH_TLS_PSK"])

def do_test(args, stderr_expected, rc_expected):
    client_run(mosq_paths.mosquitto_pub, args, stderr_expected, rc_expected)


if __name__ == '__main__':
    # Missing args
    do_test(['--psk'], "Error: --psk argument given but no key specified.", 1)
    do_test(['--psk-identity'], "Error: --psk-identity argument given but no identity specified.", 1)

    # Invalid combinations
    do_test(['--cafile', 'file', '--psk', 'key'], "Error: Only one of --psk or --cafile/--capath may be used at once.", 1)
    do_test(['--capath', 'dir', '--psk', 'key'], "Error: Only one of --psk or --cafile/--capath may be used at once.", 1)
    do_test(['--psk', 'key'], "Error: --psk-identity required if --psk used.", 1)
    
