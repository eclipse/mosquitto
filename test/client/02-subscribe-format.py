#!/usr/bin/env python3

#

from mosq_test_helper import *
import platform

mosq_test.require_features(["WITH_BROKER"])

def do_test(port, format_str, expected_outputs, proto_ver=4, payload="message"):
    rc = 1

    if proto_ver == 5:
        V = 'mqttv5'
    elif proto_ver == 4:
        V = 'mqttv311'
    else:
        V = 'mqttv31'

    env = {
        'XDG_CONFIG_HOME':'/tmp/missing'
    }
    env = mosq_test.env_add_ld_library_path(env)
    cmd = [mosq_paths.mosquitto_sub,
            '-p', str(port),
            '-q', '1',
            '-t', '02/sub/format/test',
            '-C', '1',
            '-V', V,
            '-F', format_str
            ]

    if proto_ver == 5:
        cmd += ['-D', 'subscribe', 'subscription-identifier', '56']

    props = mqtt5_props.gen_byte_prop(mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 1)
    props += mqtt5_props.gen_uint32_prop(mqtt5_props.MESSAGE_EXPIRY_INTERVAL, 3600)
    props += mqtt5_props.gen_string_prop(mqtt5_props.CONTENT_TYPE, "plain/text")
    props += mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "/dev/null")
    #props += mqtt5_props.gen_string_prop(mqtt5_props.CORRELATION_DATA, "2357289375902345")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "name1", "value1")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "name2", "value2")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "name3", "value3")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "name4", "value4")
    if proto_ver == 5:
        publish_packet = mqtt_packets.gen_publish("02/sub/format/test", qos=0, payload=payload, properties=props, proto_ver=proto_ver, retain=True)
    else:
        publish_packet = mqtt_packets.gen_publish("02/sub/format/test", qos=0, payload=payload, proto_ver=proto_ver, retain=True)

    sock = mosq_test.pub_helper(port=port, proto_ver=proto_ver)
    sock.send(publish_packet)

    sub = subprocess.run(cmd, capture_output=True, env=env)

    have_match = False
    for expected_output in expected_outputs:
        stdout = sub.stdout.decode('utf-8')
        if stdout.startswith(expected_output):
            rc = sub.returncode
            have_match = True
            break
    sock.close()
    if have_match == False:
        print(f"input: {format_str}")
        print("expected: (%d) %s" % (len(expected_outputs), expected_outputs))
        print("actual:   (%d) %s"  % (len(stdout), stdout))
        raise ValueError("no match")


if __name__ == '__main__':
    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        do_test(port, '%%', ['%'])
        do_test(port, '%A', ['']) # missing
        do_test(port, '%C', ['']) # missing
        do_test(port, '%2C', ['  ']) # missing
        do_test(port, '%C', ['plain/text'], proto_ver=5)
        do_test(port, '%D', ['']) # missing
        do_test(port, '%E', ['']) # missing
        do_test(port, '%E', ['3600','3599'], proto_ver=5)
        do_test(port, '%F', ['']) # missing
        do_test(port, '%F', ['1'], proto_ver=5)
        do_test(port, '%l', ['7']) # strlen("message")
        do_test(port, '%02l', ['07']) # strlen("message")
        do_test(port, '%2l', [' 7']) # strlen("message")
        do_test(port, '%-2l', ['7 ']) # strlen("message")
        do_test(port, '%m', ['0'])
        do_test(port, '%P', ['']) # missing
        do_test(port, '%P', ['name1:value1 name2:value2 name3:value3 name4:value4'], proto_ver=5)
        do_test(port, '%p', ['message'])
        do_test(port, '%-12p', ['message     '])
        do_test(port, '%q', ['0'])
        do_test(port, '%R', ['']) # missing
        do_test(port, '%r', ['1'])
        do_test(port, '%S', ['']) # missing
        do_test(port, '%S', ['56'], proto_ver=5)
        do_test(port, '%t', ['02/sub/format/test'])
        do_test(port, '%.20t', ['02/sub/format/test'])
        do_test(port, '%-.20t', ['02/sub/format/test'])
        do_test(port, '%20t', ['  02/sub/format/test'])
        do_test(port, '%-20t', ['02/sub/format/test  '])
        do_test(port, '%10.10t', ['02/sub/for'])
        do_test(port, '%20.10t', ['          02/sub/for'])
        do_test(port, '%-20.10t', ['02/sub/for          '])
        do_test(port, '%x', ['6d657373616765'])
        do_test(port, '%.1x', ['6 d 6 5 7 3 7 3 6 1 6 7 6 5'])
        do_test(port, '%.2x', ['6d 65 73 73 61 67 65'])
        do_test(port, '%.2:x', ['6d:65:73:73:61:67:65'])
        do_test(port, '%18x', ['    6d657373616765'])
        do_test(port, '%-18x', ['6d657373616765    '])
        do_test(port, '%X', ['6D657373616765'])
        do_test(port, '\\\\', ['\\'])
        do_test(port, '\\a', ['\a'])
        #do_test(port, '\\e', ['\e')
        do_test(port, '\\n', ['\n'])
        do_test(port, '\\r', ['\r'])
        do_test(port, '\\t', ['\t'])
        do_test(port, '\\v', ['\v'])
        do_test(port, '@@', ['@'])
        do_test(port, 'text', ['text'])
        if platform.system() != 'Darwin' and platform.system() != 'Windows':
            do_test(port, '%.3d', ['2.718'], payload=struct.pack('BBBBBBBB', 0x58, 0x39, 0xB4, 0xC8, 0x76, 0xBE, 0x05, 0x40))
            do_test(port, '%.3f', ['0.707'], payload=struct.pack('BBBB', 0xF4, 0xFD, 0x34, 0x3F))
