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
    pub.wait()
    (stdo, stde) = pub.communicate()
    if pub.returncode != rc_expected:
        raise mosq_test.TestError(pub.returncode)
    if stderr_expected is not None and stde.decode('utf-8') != stderr_expected:
        raise mosq_test.TestError(stde)


if __name__ == '__main__':
    helps = "\nUse 'mosquitto_pub --help' to see usage.\n"

    # Usage, ignore actual text though.
    do_test(['--help'], None, 1)

    # Missing args
    do_test(['-A'], "Error: -A argument given but no address specified.\n\n" + helps, 1)
    do_test(['--cafile'], "Error: --cafile argument given but no file specified.\n\n" + helps, 1)
    do_test(['--capath'], "Error: --capath argument given but no directory specified.\n\n" + helps, 1)
    do_test(['--cert'], "Error: --cert argument given but no file specified.\n\n" + helps, 1)
    do_test(['--ciphers'], "Error: --ciphers argument given but no ciphers specified.\n\n" + helps, 1)
    do_test(['-f'], "Error: -f argument given but no file specified.\n\n" + helps, 1)
    do_test(['-h'], "Error: -h argument given but no host specified.\n\n" + helps, 1)
    do_test(['-i'], "Error: -i argument given but no id specified.\n\n" + helps, 1)
    do_test(['-I'], "Error: -I argument given but no id prefix specified.\n\n" + helps, 1)
    do_test(['-k'], "Error: -k argument given but no keepalive specified.\n\n" + helps, 1)
    do_test(['--key'], "Error: --key argument given but no file specified.\n\n" + helps, 1)
    do_test(['--keyform'], "Error: --keyform argument given but no keyform specified.\n\n" + helps, 1)
    do_test(['-L'], "Error: -L argument given but no URL specified.\n\n" + helps, 1)
    do_test(['-M'], "Error: -M argument given but max_inflight not specified.\n\n" + helps, 1)
    do_test(['-m'], "Error: -m argument given but no message specified.\n\n" + helps, 1)
    do_test(['-o'], "Error: -o argument given but no options file specified.\n\n" + helps, 1)
    do_test(['-p'], "Error: -p argument given but no port specified.\n\n" + helps, 1)
    do_test(['-P'], "Error: -P argument given but no password specified.\n\n" + helps, 1)
    do_test(['--proxy'], "Error: --proxy argument given but no proxy url specified.\n\n" + helps, 1)
    do_test(['--psk'], "Error: --psk argument given but no key specified.\n\n" + helps, 1)
    do_test(['--psk-identity'], "Error: --psk-identity argument given but no identity specified.\n\n" + helps, 1)
    do_test(['-q'], "Error: -q argument given but no QoS specified.\n\n" + helps, 1)
    do_test(['--repeat'], "Error: --repeat argument given but no count specified.\n\n" + helps, 1)
    do_test(['--repeat-delay'], "Error: --repeat-delay argument given but no time specified.\n\n" + helps, 1)
    do_test(['-t'], "Error: -t argument given but no topic specified.\n\n" + helps, 1)
    do_test(['--tls-alpn'], "Error: --tls-alpn argument given but no protocol specified.\n\n" + helps, 1)
    do_test(['--tls-engine'], "Error: --tls-engine argument given but no engine_id specified.\n\n" + helps, 1)
    do_test(['--tls-engine-kpass-sha1'], "Error: --tls-engine-kpass-sha1 argument given but no kpass sha1 specified.\n\n" + helps, 1)
    do_test(['--tls-version'], "Error: --tls-version argument given but no version specified.\n\n" + helps, 1)
    do_test(['-u'], "Error: -u argument given but no username specified.\n\n" + helps, 1)
    do_test(['--unix'], "Error: --unix argument given but no socket path specified.\n\n" + helps, 1)
    do_test(['-V'], "Error: --protocol-version argument given but no version specified.\n\n" + helps, 1)
    do_test(['--will-payload'], "Error: --will-payload argument given but no will payload specified.\n\n" + helps, 1)
    do_test(['--will-qos'], "Error: --will-qos argument given but no will QoS specified.\n\n" + helps, 1)
    do_test(['--will-topic'], "Error: --will-topic argument given but no will topic specified.\n\n" + helps, 1)
    do_test(['-x'], "Error: -x argument given but no session expiry interval specified.\n\n" + helps, 1)

    do_test(['-V', '5', '-D'], "Error: --property argument given but not enough arguments specified.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect'], "Error: --property argument given but not enough arguments specified.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'receive-maximum'], "Error: --property argument given but not enough arguments specified.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'invalid', 'receive-maximum', '1'], "Error: Invalid command given in --property argument.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'invalid', '1'], "Error: Invalid property name given in --property argument.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'will-delay-interval', '1'], "Error: will-delay-interval property not allowed for connect in --property argument.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'user-property', 'key'], "Error: --property argument given but not enough arguments specified.\n\n" + helps, 1)

    # Invalid combinations
    do_test(['-i', 'id', '-I', 'id-prefix'], "Error: -i and -I argument cannot be used together.\n\n" + helps, 1)
    do_test(['-I', 'id-prefix', '-i', 'id'], "Error: -i and -I argument cannot be used together.\n\n" + helps, 1)
    do_test(['--will-payload', 'payload'], "Error: Will payload given, but no will topic given.\n" + helps, 1)
    do_test(['--will-retain'], "Error: Will retain given, but no will topic given.\n" + helps, 1)
    do_test(['--cert', 'file'], "Error: Both certfile and keyfile must be provided if one of them is set.\n" + helps, 1)
    do_test(['--key', 'file'], "Error: Both certfile and keyfile must be provided if one of them is set.\n" + helps, 1)
    do_test(['--keyform', 'file'], "Error: If keyform is set, keyfile must be also specified.\n" + helps, 1)
    do_test(['--tls-engine-kpass-sha1', 'hash'], "Error: when using tls-engine-kpass-sha1, both tls-engine and keyform must also be provided.\n" + helps, 1)
    do_test(['--cafile', 'file', '--psk', 'key'], "Error: Only one of --psk or --cafile/--capath may be used at once.\n" + helps, 1)
    do_test(['--capath', 'dir', '--psk', 'key'], "Error: Only one of --psk or --cafile/--capath may be used at once.\n" + helps, 1)
    do_test(['--psk', 'key'], "Error: --psk-identity required if --psk used.\n" + helps, 1)
    do_test(['-V', 'mqttv5', '-x', '-1'], "Error: You must provide a client id if you are using an infinite session expiry interval.\n" + helps, 1)
    do_test(['-V', 'mqttv311', '-c'], "Error: You must provide a client id if you are using the -c option.\n" + helps, 1)


    # Mixed message types
    do_test(['-m', 'message', '-f', 'file'], "Error: Only one type of message can be sent at once.\n\n" + helps, 1)
    do_test(['-m', 'message', '-l'], "Error: Only one type of message can be sent at once.\n\n" + helps, 1)
    do_test(['-l', '-m', 'message'], "Error: Only one type of message can be sent at once.\n\n" + helps, 1)
    do_test(['-l', '-n'], "Error: Only one type of message can be sent at once.\n\n" + helps, 1)
    do_test(['-l', '-s'], "Error: Only one type of message can be sent at once.\n\n" + helps, 1)

    # Invalid values
    do_test(['-t', 'topic', '-f', 'missing'], "Error: Unable to open file \"missing\".\nError loading input file \"missing\".\n", 1)
    do_test(['-k', '-1'], "Error: Invalid keepalive given, it must be between 5 and 65535 inclusive.\n\n" + helps, 1)
    do_test(['-k', '65536'], "Error: Invalid keepalive given, it must be between 5 and 65535 inclusive.\n\n" + helps, 1)
    do_test(['-M', '0'], "Error: Maximum inflight messages must be greater than 0.\n\n" + helps, 1)
    do_test(['-p', '-1'], "Error: Invalid port given: -1\n" + helps, 1)
    do_test(['-p', '65536'], "Error: Invalid port given: 65536\n" + helps, 1)
    do_test(['-q', '-1'], "Error: Invalid QoS given: -1\n" + helps, 1)
    do_test(['-q', '3'], "Error: Invalid QoS given: 3\n" + helps, 1)
    do_test(['--repeat-delay', '-1'], "Error: --repeat-delay argument must be >=0.0.\n\n" + helps, 1)
    do_test(['-t', 'topic/+'], "Error: Invalid publish topic 'topic/+', does it contain '+' or '#'?\n" + helps, 1)
    do_test(['-t', 'topic/#'], "Error: Invalid publish topic 'topic/#', does it contain '+' or '#'?\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'request-problem-information', '-1'], "Error: Property value (-1) out of range for property request-problem-information.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'request-problem-information', '256'], "Error: Property value (256) out of range for property request-problem-information.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'receive-maximum', '-1'], "Error: Property value (-1) out of range for property receive-maximum.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'receive-maximum', '65536'], "Error: Property value (65536) out of range for property receive-maximum.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'session-expiry-interval', '-1'], "Error: Property value (-1) out of range for property session-expiry-interval.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'session-expiry-interval', '4294967296'], "Error: Property value (4294967296) out of range for property session-expiry-interval.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'publish', 'subscription-identifier', '1'], "Error: subscription-identifier property not supported for publish in --property argument.\n\n" + helps, 1)
    do_test(['-t','topic','-m','1', '--cafile', 'missing'], "Error: Problem setting TLS options: File not found.\n", 1)

    # Unknown options
    do_test(['--unknown'], "Error: Unknown option '--unknown'.\n" + helps, 1)
    do_test(['-C', '1'], "Error: Unknown option '-C'.\n" + helps, 1)
    do_test(['-e', 'response-topic'], "Error: Unknown option '-e'.\n" + helps, 1)
    do_test(['-E'], "Error: Unknown option '-E'.\n" + helps, 1)
    do_test(['-F', '%p'], "Error: Unknown option '-F'.\n" + helps, 1)
    do_test(['-N'], "Error: Unknown option '-N'.\n" + helps, 1)
    do_test(['--pretty'], "Error: Unknown option '--pretty'.\n" + helps, 1)
    do_test(['-R'], "Error: Unknown option '-R'.\n" + helps, 1)
    do_test(['--random-filter'], "Error: Unknown option '--random-filter'.\n" + helps, 1)
    do_test(['--remove-retained'], "Error: Unknown option '--remove-retained'.\n" + helps, 1)
    do_test(['--retain-as-published'], "Error: Unknown option '--retain-as-published'.\n" + helps, 1)
    do_test(['--retained-only'], "Error: Unknown option '--retained-only'.\n" + helps, 1)
    do_test(['-T'], "Error: Unknown option '-T'.\n" + helps, 1)
    do_test(['-U'], "Error: Unknown option '-U'.\n" + helps, 1)
    do_test(['-v'], "Error: Unknown option '-v'.\n" + helps, 1)
    do_test(['-W'], "Error: Unknown option '-W'.\n" + helps, 1)
    do_test(['-w'], "Error: Unknown option '-w'.\n" + helps, 1)
