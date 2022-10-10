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

    # Usage and version, ignore actual text though.
    do_test(['--help'], None, 1)
    do_test(['--version'], None, 1)

    # Missing args
    do_test(['-A'], "Error: -A argument given but no address specified.\n\n" + helps, 1)
    do_test(['-C'], "Error: -C argument given but no count specified.\n\n" + helps, 1)
    do_test(['-h'], "Error: -h argument given but no host specified.\n\n" + helps, 1)
    do_test(['-i'], "Error: -i argument given but no id specified.\n\n" + helps, 1)
    do_test(['-I'], "Error: -I argument given but no id prefix specified.\n\n" + helps, 1)
    do_test(['-k'], "Error: -k argument given but no keepalive specified.\n\n" + helps, 1)
    do_test(['-L'], "Error: -L argument given but no URL specified.\n\n" + helps, 1)
    do_test(['-M'], "Error: -M argument given but max_inflight not specified.\n\n" + helps, 1)
    do_test(['-o'], "Error: -o argument given but no options file specified.\n\n" + helps, 1)
    do_test(['-p'], "Error: -p argument given but no port specified.\n\n" + helps, 1)
    do_test(['-P'], "Error: -P argument given but no password specified.\n\n" + helps, 1)
    do_test(['--proxy'], "Error: --proxy argument given but no proxy url specified.\n\n" + helps, 1)
    do_test(['--random-filter'], "Error: --random-filter argument given but no chance specified.\n\n" + helps, 1)
    do_test(['-q'], "Error: -q argument given but no QoS specified.\n\n" + helps, 1)
    do_test(['-t'], "Error: -t argument given but no topic specified.\n\n" + helps, 1)
    do_test(['-u'], "Error: -u argument given but no username specified.\n\n" + helps, 1)
    do_test(['--unix'], "Error: --unix argument given but no socket path specified.\n\n" + helps, 1)
    do_test(['-V'], "Error: --protocol-version argument given but no version specified.\n\n" + helps, 1)
    do_test(['--will-payload'], "Error: --will-payload argument given but no will payload specified.\n\n" + helps, 1)
    do_test(['--will-qos'], "Error: --will-qos argument given but no will QoS specified.\n\n" + helps, 1)
    do_test(['--will-topic'], "Error: --will-topic argument given but no will topic specified.\n\n" + helps, 1)
    do_test(['-x'], "Error: -x argument given but no session expiry interval specified.\n\n" + helps, 1)
    do_test(['-F'], "Error: -F argument given but no format specified.\n\n" + helps, 1)
    do_test(['-o'], "Error: -o argument given but no options file specified.\n\n" + helps, 1)
    do_test(['-T'], "Error: -T argument given but no topic filter specified.\n\n" + helps, 1)
    do_test(['-U'], "Error: -U argument given but no unsubscribe topic specified.\n\n" + helps, 1)
    do_test(['-W'], "Error: -W argument given but no timeout specified.\n\n" + helps, 1)
    do_test(['--will-payload', 'payload'], "Error: Will payload given, but no will topic given.\n" + helps, 1)
    # No -t or -U
    do_test([], "Error: You must specify a topic to subscribe to (-t) or unsubscribe from (-U).\n" + helps, 1)

    # Invalid combinations
    do_test(['-i', 'id', '-I', 'id-prefix'], "Error: -i and -I argument cannot be used together.\n\n" + helps, 1)
    do_test(['-I', 'id-prefix', '-i', 'id'], "Error: -i and -I argument cannot be used together.\n\n" + helps, 1)

    # Duplicate options
    do_test(['-o', 'file1', '-o', 'file2'], "Error: Duplicate -o argument given.\n\n" + helps, 1)

    # Invalid output format
    do_test(['-F', '%'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '%0'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '%-'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '%1'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '%.'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '%.1'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '%Z'], "Error: Invalid format specifier 'Z'.\n" + helps, 1)
    do_test(['-F', '@'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '\\'], "Error: Incomplete escape specifier.\n" + helps, 1)
    do_test(['-F', '\\Z'], "Error: Invalid escape specifier 'Z'.\n" + helps, 1)

    # Invalid values
    do_test(['-k', '-1'], "Error: Invalid keepalive given, it must be between 5 and 65535 inclusive.\n\n" + helps, 1)
    do_test(['-k', '65536'], "Error: Invalid keepalive given, it must be between 5 and 65535 inclusive.\n\n" + helps, 1)
    do_test(['-M', '0'], "Error: Maximum inflight messages must be greater than 0.\n\n" + helps, 1)
    do_test(['-p', '-1'], "Error: Invalid port given: -1\n" + helps, 1)
    do_test(['-p', '65536'], "Error: Invalid port given: 65536\n" + helps, 1)
    do_test(['-q', '-1'], "Error: Invalid QoS given: -1\n" + helps, 1)
    do_test(['-q', '3'], "Error: Invalid QoS given: 3\n" + helps, 1)
    do_test(['-C', '0'], "Error: Invalid message count \"0\".\n\n" + helps, 1)
    do_test(['-L', 'invalid://'], "Error: Unsupported URL scheme.\n\n" + helps, 1)
    do_test(['-L', 'mqtt://localhost'], "Error: Invalid URL for -L argument specified - topic missing.\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'request-problem-information', '-1'], "Error: Property value (-1) out of range for property request-problem-information.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'request-problem-information', '256'], "Error: Property value (256) out of range for property request-problem-information.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'receive-maximum', '-1'], "Error: Property value (-1) out of range for property receive-maximum.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'receive-maximum', '65536'], "Error: Property value (65536) out of range for property receive-maximum.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'session-expiry-interval', '-1'], "Error: Property value (-1) out of range for property session-expiry-interval.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'connect', 'session-expiry-interval', '4294967296'], "Error: Property value (4294967296) out of range for property session-expiry-interval.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'subscribe', 'subscription-identifier', '-1'], "Error: Property value (-1) out of range for property subscription-identifier.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'subscribe', 'subscription-identifier', '4294967296'], "Error: Property value (4294967296) out of range for property subscription-identifier.\n\n" + helps, 1)
    do_test(['-V', '5', '-D', 'subscribe', 'topic-alias', '1'], "Error: topic-alias property not allowed for subscribe in --property argument.\n\n" + helps, 1)
    do_test(['-T', '++'], "Error: Invalid filter topic '++', are all '+' and '#' wildcards correct?\n" + helps, 1)
    do_test(['-U', '++'], "Error: Invalid unsubscribe topic '++', are all '+' and '#' wildcards correct?\n" + helps, 1)
    do_test(['-V', '0'], "Error: Invalid protocol version argument given.\n\n" + helps, 1)
    do_test(['-W', '0'], "Error: Invalid timeout \"0\".\n\n" + helps, 1)
    do_test(['--will-qos', '-1'], "Error: Invalid will QoS -1.\n\n" + helps, 1)
    do_test(['--will-qos', '3'], "Error: Invalid will QoS 3.\n\n" + helps, 1)
    do_test(['--will-topic', '+'], "Error: Invalid will topic '+', does it contain '+' or '#'?\n" + helps, 1)
    do_test(['-x', 'A'], "Error: session-expiry-interval not a number.\n\n" + helps, 1)
    do_test(['-x', '-2'], "Error: session-expiry-interval out of range.\n\n" + helps, 1)
    do_test(['-x', '4294967296'], "Error: session-expiry-interval out of range.\n\n" + helps, 1)

    # Unknown options
    do_test(['--unknown'], "Error: Unknown option '--unknown'.\n" + helps, 1)
    do_test(['-l'], "Error: Unknown option '-l'.\n" + helps, 1)
    do_test(['-m'], "Error: Unknown option '-m'.\n" + helps, 1)
    do_test(['-n'], "Error: Unknown option '-n'.\n" + helps, 1)
    do_test(['-r'], "Error: Unknown option '-r'.\n" + helps, 1)
    do_test(['--repeat'], "Error: Unknown option '--repeat'.\n" + helps, 1)
    do_test(['--repeat-delay'], "Error: Unknown option '--repeat-delay'.\n" + helps, 1)
    do_test(['-s'], "Error: Unknown option '-s'.\n" + helps, 1)
