#!/usr/bin/env python3

#

from mosq_test_helper import *

def do_test(args, stderr_expected, rc_expected):
    rc = 1

    port = mosq_test.get_port()

    env = {
            'LD_LIBRARY_PATH': mosq_test.get_build_root() + '/lib',
            'XDG_CONFIG_HOME':'/tmp/missing'
            }
    cmd = ['../../client/mosquitto_sub'] + args

    sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if mosq_test.wait_for_subprocess(sub):
        print("sub not terminated")
        raise mosq_test.TestError(1)
    (stdo, stde) = sub.communicate()
    if sub.returncode != rc_expected:
        raise mosq_test.TestError(sub.returncode)
    if stderr_expected is not None and stde.decode('utf-8') != stderr_expected:
        raise mosq_test.TestError(stde)


if __name__ == '__main__':
    helps = "\nUse 'mosquitto_sub --help' to see usage.\n"

    # Missing args for TLS-PSK related options
    do_test(['--psk'], "Error: --psk argument given but no key specified.\n\n" + helps, 1)
    do_test(['--psk-identity'], "Error: --psk-identity argument given but no identity specified.\n\n" + helps, 1)
