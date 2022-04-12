#!/usr/bin/env python3

#

from mosq_test_helper import *

def do_test(format_str, expected_output, proto_ver=4):
    rc = 1

    port = mosq_test.get_port()

    if proto_ver == 5:
        V = 'mqttv5'
    elif proto_ver == 4:
        V = 'mqttv311'
    else:
        V = 'mqttv31'

    env = {
            'LD_LIBRARY_PATH':'../../lib',
            'XDG_CONFIG_HOME':'/tmp/missing'
            }
    cmd = ['../../client/mosquitto_sub',
            '-p', str(port),
            '-q', '1',
            '-t', '02/sub/format/test',
            '-C', '1',
            '-V', V,
            '-F', format_str
            ]

    if proto_ver == 5:
        cmd += ['-D', 'subscribe', 'subscription-identifier', '56']

    payload = "message"
    props = mqtt5_props.gen_byte_prop(mqtt5_props.PROP_PAYLOAD_FORMAT_INDICATOR, 1)
    props += mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_MESSAGE_EXPIRY_INTERVAL, 3600)
    props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_CONTENT_TYPE, "plain/text")
    props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_RESPONSE_TOPIC, "/dev/null")
    #props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_CORRELATION_DATA, "2357289375902345")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "name1", "value1")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "name2", "value2")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "name3", "value3")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "name4", "value4")
    if proto_ver == 5:
        publish_packet = mosq_test.gen_publish("02/sub/format/test", qos=0, payload=payload, properties=props, proto_ver=proto_ver)
    else:
        publish_packet = mosq_test.gen_publish("02/sub/format/test", qos=0, payload=payload, proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.pub_helper(port=port, proto_ver=proto_ver)

        sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        time.sleep(0.1)
        sock.send(publish_packet)
        sub_terminate_rc = 0
        if mosq_test.wait_for_subprocess(sub):
            print("sub not terminated")
            sub_terminate_rc = 1
        (stdo, stde) = sub.communicate()
        if stdo.decode('utf-8') == expected_output:
            rc = sub_terminate_rc
        else:
            print("expected: (%d) %s" % (len(expected_output), expected_output))
            print("actual:   (%d) %s"  % (len(stdo.decode('utf-8')), stdo.decode('utf-8')))
        sock.close()
    except mosq_test.TestError:
        pass
    except Exception as e:
        print(e)
    finally:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)


do_test('%%', '%\n')
do_test('%A', '\n') # missing
do_test('%C', '\n') # missing
do_test('%2C', '  \n') # missing
do_test('%C', 'plain/text\n', proto_ver=5)
do_test('%D', '\n') # missing
do_test('%E', '\n') # missing
do_test('%E', '3600\n', proto_ver=5)
do_test('%F', '\n') # missing
do_test('%F', '1\n', proto_ver=5)
do_test('%l', '7\n') # strlen("message")
do_test('%02l', '07\n') # strlen("message")
do_test('%2l', ' 7\n') # strlen("message")
do_test('%-2l', '7 \n') # strlen("message")
do_test('%m', '0\n')
do_test('%P', '\n') # missing
do_test('%P', 'name1:value1 name2:value2 name3:value3 name4:value4\n', proto_ver=5)
do_test('%p', 'message\n')
do_test('%-12p', 'message     \n')
do_test('%q', '0\n')
do_test('%R', '\n') # missing
do_test('%r', '0\n')
do_test('%S', '\n') # missing
do_test('%S', '56\n', proto_ver=5)
do_test('%t', '02/sub/format/test\n')
do_test('%.20t', '02/sub/format/test\n')
do_test('%-.20t', '02/sub/format/test\n')
do_test('%20t', '  02/sub/format/test\n')
do_test('%-20t', '02/sub/format/test  \n')
do_test('%10.10t', '02/sub/for\n')
do_test('%20.10t', '          02/sub/for\n')
do_test('%-20.10t', '02/sub/for          \n')
do_test('%x', '6d657373616765\n')
do_test('%18x', '    6d657373616765\n')
do_test('%-18x', '6d657373616765    \n')
do_test('%X', '6D657373616765\n')
do_test('\\\\', '\\\n')
do_test('\\a', '\a\n')
#do_test('\\e', '\e\n')
do_test('\\n', '\n\n')
do_test('\\r', '\r\n')
do_test('\\t', '\t\n')
do_test('\\v', '\v\n')
do_test('@@', '@\n')
do_test('text', 'text\n')
