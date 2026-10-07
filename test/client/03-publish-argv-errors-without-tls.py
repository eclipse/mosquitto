#!/usr/bin/env python3

#

from mosq_test_helper import *

def do_test(args, stderr_expected, rc_expected):
    client_run(mosq_paths.mosquitto_pub, args, stderr_expected, rc_expected)


if __name__ == '__main__':
    # Usage, version, ignore actual text though.
    do_test(['--help'], None, 1)
    do_test(['--version'], None, 1)

    # Missing args
    do_test([], "Error: Both topic and message must be supplied.", 1)
    do_test(['-A'], "Error: -A argument given but no address specified.", 1)
    do_test(['-f'], "Error: -f argument given but no file specified.", 1)
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
    do_test(['--repeat'], "Error: --repeat argument given but no count specified.", 1)
    do_test(['--repeat-delay'], "Error: --repeat-delay argument given but no time specified.", 1)
    do_test(['-t'], "Error: -t argument given but no topic specified.", 1)
    do_test(['-u'], "Error: -u argument given but no username specified.", 1)
    do_test(['--unix'], "Error: --unix argument given but no socket path specified.", 1)
    do_test(['-V'], "Error: --protocol-version argument given but no version specified.", 1)
    do_test(['--will-payload'], "Error: --will-payload argument given but no will payload specified.", 1)
    do_test(['--will-qos'], "Error: --will-qos argument given but no will QoS specified.", 1)
    do_test(['--will-topic'], "Error: --will-topic argument given but no will topic specified.", 1)
    do_test(['-x'], "Error: -x argument given but no session expiry interval specified.", 1)

    do_test(['-V', '5', '-D'], "Error: --property argument given but not enough arguments specified.", 1)
    do_test(['-V', '5', '-D', 'connect'], "Error: --property argument given but not enough arguments specified.", 1)
    do_test(['-V', '5', '-D', 'connect', 'receive-maximum'], "Error: --property argument given but not enough arguments specified.", 1)
    do_test(['-V', '5', '-D', 'invalid', 'receive-maximum', '1'], "Error: Invalid command invalid given in --property argument.", 1)
    do_test(['-V', '5', '-D', 'connect', 'invalid', '1'], "Error: Invalid property name invalid given in --property argument.", 1)
    do_test(['-V', '5', '-D', 'connect', 'will-delay-interval', '1'], "Error: will-delay-interval property not allowed for connect in --property argument.", 1)
    do_test(['-V', '5', '-D', 'connect', 'user-property', 'key'], "Error: --property argument given but not enough arguments specified.", 1)

    # Invalid combinations
    do_test(['-i', 'id', '-I', 'id-prefix'], "Error: -i and -I argument cannot be used together.", 1)
    do_test(['-I', 'id-prefix', '-i', 'id'], "Error: -i and -I argument cannot be used together.", 1)
    do_test(['--will-payload', 'payload'], "Error: Will payload given, but no will topic given.", 1)
    do_test(['--will-retain'], "Error: Will retain given, but no will topic given.", 1)
    do_test(['-V', 'mqttv5', '-x', '-1'], "Error: You must provide a client id if you are using an infinite session expiry interval.", 1)
    do_test(['-V', 'mqttv311', '-c'], "Error: You must provide a client id if you are using the -c option.", 1)


    # Mixed message types
    do_test(['-m', 'message', '-f', 'file'], "Error: Only one type of message can be sent at once.", 1)
    do_test(['-m', 'message', '-l'], "Error: Only one type of message can be sent at once.", 1)
    do_test(['-l', '-m', 'message'], "Error: Only one type of message can be sent at once.", 1)
    do_test(['-l', '-n'], "Error: Only one type of message can be sent at once.", 1)
    do_test(['-l', '-s'], "Error: Only one type of message can be sent at once.", 1)

    # Invalid values
    do_test(['-t', 'topic', '-f', 'missing'], "Error: Unable to read file \"missing\": No such file or directory.\nError loading input file \"missing\".\n", 1)
    do_test(['-k', '-1'], "Error: Invalid keepalive given, it must be between 5 and 65535 inclusive.", 1)
    do_test(['-k', '65536'], "Error: Invalid keepalive given, it must be between 5 and 65535 inclusive.", 1)
    do_test(['-M', '0'], "Error: Maximum inflight messages must be greater than 0.", 1)
    do_test(['-p', '-1'], "Error: Invalid port given: -1", 1)
    do_test(['-p', '65536'], "Error: Invalid port given: 65536", 1)
    do_test(['-q', '-1'], "Error: Invalid QoS given: -1", 1)
    do_test(['-q', '3'], "Error: Invalid QoS given: 3", 1)
    do_test(['--repeat-delay', '-1'], "Error: --repeat-delay argument must be >=0.0.", 1)
    do_test(['-t', 'topic/+'], "Error: Invalid publish topic 'topic/+', does it contain '+' or '#'?", 1)
    do_test(['-t', 'topic/#'], "Error: Invalid publish topic 'topic/#', does it contain '+' or '#'?", 1)
    do_test(['-V', '5', '-D', 'connect', 'request-problem-information', '-1'], "Error: Property value (-1) out of range for property request-problem-information.", 1)
    do_test(['-V', '5', '-D', 'connect', 'request-problem-information', '256'], "Error: Property value (256) out of range for property request-problem-information.", 1)
    do_test(['-V', '5', '-D', 'connect', 'receive-maximum', '-1'], "Error: Property value (-1) out of range for property receive-maximum.", 1)
    do_test(['-V', '5', '-D', 'connect', 'receive-maximum', '65536'], "Error: Property value (65536) out of range for property receive-maximum.", 1)
    do_test(['-V', '5', '-D', 'connect', 'session-expiry-interval', '-1'], "Error: Property value (-1) out of range for property session-expiry-interval.", 1)
    do_test(['-V', '5', '-D', 'connect', 'session-expiry-interval', '4294967296'], "Error: Property value (4294967296) out of range for property session-expiry-interval.", 1)
    do_test(['-V', '5', '-D', 'connect', 'subscription-identifier', '1'], "Error: subscription-identifier property not allowed for connect in --property argument.", 1)
    do_test(['-V', '5', '-D', 'publish', 'subscription-identifier', '1'], "Error: subscription-identifier property not supported for publish in --property argument.", 1)

    # Unknown options
    do_test(['--unknown'], "Error: Unknown option '--unknown'.", 1)
    do_test(['-C', '1'], "Error: Unknown option '-C'.", 1)
    do_test(['-e', 'response-topic'], "Error: Unknown option '-e'.", 1)
    do_test(['-E'], "Error: Unknown option '-E'.", 1)
    do_test(['-F', '%p'], "Error: Unknown option '-F'.", 1)
    do_test(['--latency'], "Error: Unknown option '--latency'.", 1)
    do_test(['--message-rate'], "Error: Unknown option '--message-rate'.", 1)
    do_test(['-N'], "Error: Unknown option '-N'.", 1)
    do_test(['--pretty'], "Error: Unknown option '--pretty'.", 1)
    do_test(['-R'], "Error: Unknown option '-R'.", 1)
    do_test(['--random-filter'], "Error: Unknown option '--random-filter'.", 1)
    do_test(['--remove-retained'], "Error: Unknown option '--remove-retained'.", 1)
    do_test(['--retain-as-published'], "Error: Unknown option '--retain-as-published'.", 1)
    do_test(['--retain-handling', 'invalid'], "Error: Unknown option '--retain-handling'.", 1)
    do_test(['--retained-only'], "Error: Unknown option '--retained-only'.", 1)
    do_test(['-T'], "Error: Unknown option '-T'.", 1)
    do_test(['-U'], "Error: Unknown option '-U'.", 1)
    do_test(['-v'], "Error: Unknown option '-v'.", 1)
    do_test(['-W'], "Error: Unknown option '-W'.", 1)
    do_test(['-w'], "Error: Unknown option '-w'.", 1)
