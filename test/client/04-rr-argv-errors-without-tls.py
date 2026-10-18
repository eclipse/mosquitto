#!/usr/bin/env python3

#

from mosq_test_helper import *

def do_test(args, stderr_expected, rc_expected):
    client_run(mosq_paths.mosquitto_rr, args, stderr_expected, rc_expected)


if __name__ == '__main__':
    # Usage, version, ignore actual text though.
    do_test(['--help'], None, 1)
    do_test(['--version'], None, 1)

    # Missing args
    do_test(['-A'], "Error: -A argument given but no address specified.", 1)
    do_test(['-e'], "Error: -e argument given but no response topic specified.", 1)
    do_test(['-h'], "Error: -h argument given but no host specified.", 1)
    do_test(['-i'], "Error: -i argument given but no id specified.", 1)
    do_test(['-I'], "Error: -I argument given but no id prefix specified.", 1)
    do_test(['-k'], "Error: -k argument given but no keepalive specified.", 1)
    do_test(['-L'], "Error: -L argument given but no URL specified.", 1)
    do_test(['-M'], "Error: -M argument given but max_inflight not specified.", 1)
    do_test(['-m'], "Error: -m argument given but no message specified.", 1)
    do_test(['-o'], "Error: -o argument given but no options file specified.", 1)
    do_test(['-p'], "Error: -p argument given but no port specified.", 1)
    do_test(['-P'], "Error: -P argument given but no password specified.", 1)
    if mosq_test.check_features(["WITH_SOCKS"]):
        do_test(['--proxy'], "Error: --proxy argument given but no proxy url specified.", 1)
    else:
        do_test(['--proxy'], "Error: Unknown option '--proxy'.", 1)
    do_test(['-q'], "Error: -q argument given but no QoS specified.", 1)
    do_test(['-t'], "Error: -t argument given but no topic specified.", 1)
    do_test(['-u'], "Error: -u argument given but no username specified.", 1)
    do_test(['--unix'], "Error: --unix argument given but no socket path specified.", 1)
    do_test(['-V'], "Error: --protocol-version argument given but no version specified.", 1)
    do_test(['--will-payload'], "Error: --will-payload argument given but no will payload specified.", 1)
    do_test(['--will-qos'], "Error: --will-qos argument given but no will QoS specified.", 1)
    do_test(['--will-topic'], "Error: --will-topic argument given but no will topic specified.", 1)
    do_test(['-x'], "Error: -x argument given but no session expiry interval specified.", 1)
    do_test(['-F'], "Error: -F argument given but no format specified.", 1)
    do_test(['-o'], "Error: -o argument given but no options file specified.", 1)
    do_test(['-W'], "Error: -W argument given but no timeout specified.", 1)
    do_test(['--will-payload', 'payload'], "Error: Will payload given, but no will topic given.", 1)
    # No -t or -U
    do_test([], "Error: All of topic, message, and response topic must be supplied.", 1)

    # Invalid combinations
    do_test(['-i', 'id', '-I', 'id-prefix'], "Error: -i and -I argument cannot be used together.", 1)
    do_test(['-I', 'id-prefix', '-i', 'id'], "Error: -i and -I argument cannot be used together.", 1)

    # Invalid output format
    do_test(['-F', '%'], "Error: Incomplete format specifier.", 1)
    do_test(['-F', '%0'], "Error: Incomplete format specifier.", 1)
    do_test(['-F', '%-'], "Error: Incomplete format specifier.", 1)
    do_test(['-F', '%1'], "Error: Incomplete format specifier.", 1)
    do_test(['-F', '%.'], "Error: Incomplete format specifier.", 1)
    do_test(['-F', '%.1'], "Error: Incomplete format specifier.", 1)
    do_test(['-F', '%Z'], "Error: Invalid format specifier 'Z'.", 1)
    do_test(['-F', '@'], "Error: Incomplete format specifier.", 1)
    do_test(['-F', '\\'], "Error: Incomplete escape specifier.", 1)
    do_test(['-F', '\\Z'], "Error: Invalid escape specifier 'Z'.", 1)

    # Invalid values
    do_test(['-e', 'topic/+'], "Error: Invalid response topic 'topic/+', does it contain '+' or '#'?", 1)
    do_test(['-k', '-1'], "Error: Invalid keepalive given, it must be between 5 and 65535 inclusive.", 1)
    do_test(['-k', '65536'], "Error: Invalid keepalive given, it must be between 5 and 65535 inclusive.", 1)
    do_test(['-M', '0'], "Error: Maximum inflight messages must be greater than 0.", 1)
    do_test(['-p', '-1'], "Error: Invalid port given: -1", 1)
    do_test(['-p', '65536'], "Error: Invalid port given: 65536", 1)
    do_test(['-q', '-1'], "Error: Invalid QoS given: -1", 1)
    do_test(['-q', '3'], "Error: Invalid QoS given: 3", 1)
    do_test(['-L', 'invalid://'], "Error: Unsupported URL scheme.", 1)
    do_test(['-L', 'mqtt://localhost'], "Error: Invalid URL for -L argument specified - topic missing.", 1)
    do_test(['-V', '5', '-D', 'connect', 'request-problem-information', '-1'], "Error: Property value (-1) out of range for property request-problem-information.", 1)
    do_test(['-V', '5', '-D', 'connect', 'request-problem-information', '256'], "Error: Property value (256) out of range for property request-problem-information.", 1)
    do_test(['-V', '5', '-D', 'connect', 'receive-maximum', '-1'], "Error: Property value (-1) out of range for property receive-maximum.", 1)
    do_test(['-V', '5', '-D', 'connect', 'receive-maximum', '65536'], "Error: Property value (65536) out of range for property receive-maximum.", 1)
    do_test(['-V', '5', '-D', 'connect', 'session-expiry-interval', '-1'], "Error: Property value (-1) out of range for property session-expiry-interval.", 1)
    do_test(['-V', '5', '-D', 'connect', 'session-expiry-interval', '4294967296'], "Error: Property value (4294967296) out of range for property session-expiry-interval.", 1)
    do_test(['-V', '5', '-D', 'subscribe', 'subscription-identifier', '-1'], "Error: Property value (-1) out of range for property subscription-identifier.", 1)
    do_test(['-V', '5', '-D', 'subscribe', 'subscription-identifier', '4294967296'], "Error: Property value (4294967296) out of range for property subscription-identifier.", 1)
    do_test(['-V', '5', '-D', 'subscribe', 'topic-alias', '1'], "Error: topic-alias property not allowed for subscribe in --property argument.", 1)
    do_test(['-V', '0'], "Error: Invalid protocol version argument given.", 1)
    do_test(['-W', '0'], "Error: Invalid timeout \"0\".", 1)
    do_test(['--will-qos', '-1'], "Error: Invalid will QoS -1.", 1)
    do_test(['--will-qos', '3'], "Error: Invalid will QoS 3.", 1)
    do_test(['--will-topic', '+'], "Error: Invalid will topic '+', does it contain '+' or '#'?", 1)
    do_test(['-x', 'A'], "Error: session-expiry-interval not a number.", 1)
    do_test(['-x', '-2'], "Error: session-expiry-interval out of range.", 1)
    do_test(['-x', '4294967296'], "Error: session-expiry-interval out of range.", 1)
    do_test(['--retain-handling'], "Error: --retain-handling argument given but no option specified.", 1)
    do_test(['--retain-handling', 'invalid'], "Error: Unknown value 'invalid' for --retain-handling.", 1)

    # Mixed message types
    do_test(['-m', 'message', '-f', 'file'], "Error: Only one type of message can be sent at once.", 1)

    # Unknown options
    do_test(['--unknown'], "Error: Unknown option '--unknown'.", 1)
    do_test(['-l'], "Error: Unknown option '-l'.", 1)
    do_test(['--message-rate'], "Error: Unknown option '--message-rate'.", 1)
    do_test(['-r'], "Error: Unknown option '-r'.", 1)
    do_test(['--repeat'], "Error: Unknown option '--repeat'.", 1)
    do_test(['--repeat-delay'], "Error: Unknown option '--repeat-delay'.", 1)
