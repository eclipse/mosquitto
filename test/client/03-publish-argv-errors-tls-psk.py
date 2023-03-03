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
    cmd = ['../../client/mosquitto_pub'] + args

    pub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if mosq_test.wait_for_subprocess(pub):
        print("pub not terminated")
        raise mosq_test.TestError(1)
    (stdo, stde) = pub.communicate()
    if pub.returncode != rc_expected:
        raise mosq_test.TestError(pub.returncode)
    if stderr_expected is not None and stde.decode('utf-8') != stderr_expected:
        raise mosq_test.TestError(stde)


if __name__ == '__main__':
    helps = "\nUse 'mosquitto_pub --help' to see usage.\n"

    # Missing args
    do_test(['--psk'], "Error: --psk argument given but no key specified.\n\n" + helps, 1)
    do_test(['--psk-identity'], "Error: --psk-identity argument given but no identity specified.\n\n" + helps, 1)

    # Invalid combinations
    do_test(['--cafile', 'file', '--psk', 'key'], "Error: Only one of --psk or --cafile/--capath may be used at once.\n" + helps, 1)
    do_test(['--capath', 'dir', '--psk', 'key'], "Error: Only one of --psk or --cafile/--capath may be used at once.\n" + helps, 1)
    do_test(['--psk', 'key'], "Error: --psk-identity required if --psk used.\n" + helps, 1)
    
