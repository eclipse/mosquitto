#!/usr/bin/env python3

#

from mosq_test_helper import *
import json

def do_test(proto_ver):
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
            '-F', '%j',
            '-t', '02/sub/format/json/properties/test',
            '-V', V,
            '-C', '1'
            ]

    props = mqtt5_props.gen_byte_prop(mqtt5_props.PROP_PAYLOAD_FORMAT_INDICATOR, 1)
    props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_CONTENT_TYPE, "plain/text")
    props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_RESPONSE_TOPIC, "/dev/null")
    #props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_CORRELATION_DATA, "2357289375902345")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "name", "value")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "name", "value")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "name", "value")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "name", "value")
    publish_packet = mosq_test.gen_publish("02/sub/format/json/properties/test", mid=1, qos=1, payload="message", proto_ver=proto_ver, properties=props)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    expected = {
        "tst": "",
        "topic": "02/sub/format/json/properties/test",
        "qos": 1,
        "retain": 0,
        "payloadlen": 7,
        "mid": 1,
        "properties": {
            "payload-format-indicator": 1,
            "content-type": "plain/text",
            "response-topic": "/dev/null",
            "user-properties": [
                {"name": "value"},
                {"name": "value"},
                {"name": "value"},
                {"name": "value"}
            ]
        },
        "payload": "message"
    }

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
        j = json.loads(stdo.decode('utf-8'))
        j['tst'] = ""

        if j == expected:
            rc = sub_terminate_rc
        else:
            print(json.dumps(j))
            print(json.dumps(expected))
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
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


do_test(proto_ver=5)
