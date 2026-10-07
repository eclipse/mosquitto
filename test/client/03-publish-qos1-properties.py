#!/usr/bin/env python3

#

from mosq_test_helper import *

mosq_test.require_features(["WITH_BROKER"])

def do_test(port, proto_ver):
    rc = 1

    env = {
        'XDG_CONFIG_HOME':'/tmp/missing'
    }
    env = mosq_test.env_add_ld_library_path(env)
    if proto_ver == 5:
        V = 'mqttv5'
    elif proto_ver == 4:
        V = 'mqttv311'
    else:
        V = 'mqttv31'

    cmd = [mosq_paths.mosquitto_pub,
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
    props = mqtt5_props.gen_string_prop(mqtt5_props.CONTENT_TYPE, "application/json")
    props += mqtt5_props.gen_string_prop(mqtt5_props.CORRELATION_DATA, "some-data")
    props += mqtt5_props.gen_byte_prop(mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 1)
    props += mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "/dev/null")
    props += mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "publish", "up")
    props += mqtt5_props.gen_uint32_prop(mqtt5_props.MESSAGE_EXPIRY_INTERVAL, 59)
    publish_packet = mqtt_packets.gen_publish("03/pub/qos1/test/properties", qos=1, mid=mid, payload="message", proto_ver=proto_ver, properties=props)
    puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver, reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS)

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

    if rc:
        print(stde.decode('utf-8'))
        print("proto_ver=%d" % (proto_ver))


if __name__ == '__main__':
    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        do_test(port, proto_ver=5)
