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
    cmd = ['../../client/mosquitto_rr'] + args

    sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    sub.wait()
    (stdo, stde) = sub.communicate()
    if sub.returncode != rc_expected:
        raise mosq_test.TestError(sub.returncode)
    if stderr_expected is not None and stde.decode('utf-8') != stderr_expected:
        raise mosq_test.TestError(stde)


if __name__ == '__main__':
    helps = "\nUse 'mosquitto_rr --help' to see usage.\n"

    # Missing args for TLS related options
    do_test(['--cafile'], "Error: --cafile argument given but no file specified.\n\n" + helps, 1)
    do_test(['--capath'], "Error: --capath argument given but no directory specified.\n\n" + helps, 1)
    do_test(['--cert'], "Error: --cert argument given but no file specified.\n\n" + helps, 1)
    do_test(['--ciphers'], "Error: --ciphers argument given but no ciphers specified.\n\n" + helps, 1)
    do_test(['--key'], "Error: --key argument given but no file specified.\n\n" + helps, 1)
    do_test(['--keyform'], "Error: --keyform argument given but no keyform specified.\n\n" + helps, 1)
    do_test(['--tls-alpn'], "Error: --tls-alpn argument given but no protocol specified.\n\n" + helps, 1)
    do_test(['--tls-engine'], "Error: --tls-engine argument given but no engine_id specified.\n\n" + helps, 1)
    do_test(['--tls-engine-kpass-sha1'], "Error: --tls-engine-kpass-sha1 argument given but no kpass sha1 specified.\n\n" + helps, 1)
    do_test(['--tls-version'], "Error: --tls-version argument given but no version specified.\n\n" + helps, 1)
