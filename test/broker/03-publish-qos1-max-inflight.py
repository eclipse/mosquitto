#!/usr/bin/env python3

# Test whether a PUBLISH to a topic with QoS 1 results in the correct packet flow.
# With max_inflight_messages set to 1

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("port %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("max_inflight_messages 1\n")

def do_test(proto_ver):
    rc = 1
    keepalive = 60
    connect_packet = mosq_test.gen_connect("pub-qos1-test", keepalive=keepalive, proto_ver=proto_ver)
    properties = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS_MAXIMUM, 10) \
        + mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_RECEIVE_MAXIMUM, 1)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver, properties=properties, property_helper=False)

    mid = 311
    publish_packet = mosq_test.gen_publish("pub/qos1/test", qos=1, mid=mid, payload="message", proto_ver=proto_ver)
    puback_packet = mosq_test.gen_puback(mid, reason_code=mqtt5_rc.MQTT_RC_NO_MATCHING_SUBSCRIBERS, proto_ver=proto_ver)

    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port, timeout=10)
        mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")

        rc = 0

        sock.close()
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        broker.terminate()
        broker.wait()
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


do_test(proto_ver=4)
do_test(proto_ver=5)
exit(0)

