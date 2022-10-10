#!/usr/bin/env python3

#

from mosq_test_helper import *

def do_test(proto_ver):
    rc = 1

    port = mosq_test.get_port()

    env = {
            'LD_LIBRARY_PATH': mosq_test.get_build_root() + '/lib',
            'XDG_CONFIG_HOME':'/tmp/missing'
            }
    if proto_ver == 5:
        V = 'mqttv5'
    elif proto_ver == 4:
        V = 'mqttv311'
    else:
        V = 'mqttv31'

    cmd = ['../../client/mosquitto_pub',
            '-p', str(port),
            '-q', '1',
            '-t', '03/pub/qos1/test/properties',
            '-m', 'message',
            '-V', V,
	        '-D', 'publish', 'content-type', 'application/json',
	        '-D', 'publish', 'correlation-data', 'some-data',
	        '-D', 'publish', 'message-expiry-interval', '59',
	        '-D', 'publish', 'payload-format-indicator', '1',
	        '-D', 'publish', 'response-topic', '/dev/null',
	        '-D', 'publish', 'topic-alias', '4',
	        '-D', 'publish', 'user-property', 'publish', 'up'
            ]

    mid = 1
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_CONTENT_TYPE, "application/json")
    props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_CORRELATION_DATA, "some-data")
    props += mqtt5_props.gen_byte_prop(mqtt5_props.PROP_PAYLOAD_FORMAT_INDICATOR, 1)
    props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_RESPONSE_TOPIC, "/dev/null")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "publish", "up")
    props += mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_MESSAGE_EXPIRY_INTERVAL, 59)
    publish_packet = mosq_test.gen_publish("03/pub/qos1/test/properties", qos=1, mid=mid, payload="message", proto_ver=proto_ver, properties=props)
    puback_packet = mosq_test.gen_puback(mid, proto_ver=proto_ver, reason_code=mqtt5_rc.MQTT_RC_NO_MATCHING_SUBSCRIBERS)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.sub_helper(port=port, topic="#", qos=1, proto_ver=5)

        pub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        pub_terminate_rc = 0
        if mosq_test.wait_for_subprocess(pub):
            print("pub not terminated")
            pub_terminate_rc = 1
        (stdo, stde) = pub.communicate()

        mosq_test.expect_packet(sock, "publish", publish_packet)
        rc = pub_terminate_rc
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
