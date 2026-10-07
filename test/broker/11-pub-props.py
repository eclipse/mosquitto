#!/usr/bin/env python3

# Does a persisted PUBLISH keep its properties?

from mosq_test_helper import *

mosq_test.require_features(["WITH_PERSISTENCE"])

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("persistence true\n")
        f.write("persistence_file mosquitto-%d.db\n" % (port))

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

rc = 1
connect_packet = mqtt_packets.gen_connect(
    "persistent-props-test", clean_session=True, proto_ver=5
)
connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

mid = 1
props = mqtt5_props.gen_byte_prop(mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 1)
props += mqtt5_props.gen_string_prop(mqtt5_props.CONTENT_TYPE, "plain/text")
props += mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "/dev/null")
props += mqtt5_props.gen_string_prop(mqtt5_props.CORRELATION_DATA, "2357289375902345")
props += mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "name", "value")
publish_packet = mqtt_packets.gen_publish("subpub/qos1", qos=1, mid=mid, payload="message", proto_ver=5, properties=props, retain=True)
puback_packet = mqtt_packets.gen_puback(mid, reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS, proto_ver=5)

publish2_packet = mqtt_packets.gen_publish("subpub/qos1", qos=0, payload="message", proto_ver=5, properties=props, retain=True)

mid = 1
subscribe_packet = mqtt_packets.gen_subscribe(mid, "subpub/qos1", 0, proto_ver=5)
suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=5)

if os.path.exists('mosquitto-%d.db' % (port)):
    os.unlink('mosquitto-%d.db' % (port))

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

(stdo1, stde1) = ("", "")
try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
    mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    mosq_test.expect_packet(sock, "publish2", publish2_packet)

    mosq_test.terminate_broker(broker)
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    stde1 = mosq_test.broker_log(broker)
    sock.close()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    mosq_test.expect_packet(sock, "publish2", publish2_packet)
    rc = 0

    sock.close()
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    mosq_test.terminate_broker(broker)
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    if rc:
        print(mosq_test.broker_log(broker))
    if os.path.exists('mosquitto-%d.db' % (port)):
        os.unlink('mosquitto-%d.db' % (port))


exit(rc)

