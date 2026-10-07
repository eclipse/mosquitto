#!/usr/bin/env python3

# Test whether a client message maintains its subscription id when persisted and restored.

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
    "persistent-subscription-test", clean_session=False, proto_ver=5, session_expiry=60
)
connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)
connack_packet2 = mqtt_packets.gen_connack(rc=0, flags=1, proto_ver=5)  # session present

mid = 1
props = mqtt5_props.gen_varint_prop(mqtt5_props.SUBSCRIPTION_IDENTIFIER, 53)
subscribe_packet = mqtt_packets.gen_subscribe(mid, "subpub/qos1", 1, proto_ver=5, properties=props)
suback_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=5)

mid = 1
props = mqtt5_props.gen_varint_prop(mqtt5_props.SUBSCRIPTION_IDENTIFIER, 53)
publish_packet2 = mqtt_packets.gen_publish("subpub/qos1", qos=1, mid=mid, payload="message", proto_ver=5, properties=props)


helper_connect_packet = mqtt_packets.gen_connect("helper", clean_session=True, proto_ver=5)
helper_connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

mid = 1
helper_publish_packet = mqtt_packets.gen_publish("subpub/qos1", qos=1, mid=mid, payload="message", proto_ver=5)
helper_puback_packet = mqtt_packets.gen_puback(mid, proto_ver=5)


if os.path.exists('mosquitto-%d.db' % (port)):
    os.unlink('mosquitto-%d.db' % (port))

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

(stdo1, stde1) = ("", "")
try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
    sock.close()

    sock = mosq_test.do_client_connect(helper_connect_packet, helper_connack_packet, timeout=20, port=port)
    mosq_test.do_send_receive(sock, helper_publish_packet, helper_puback_packet, "helper puback")
    sock.close()

    mosq_test.terminate_broker(broker)
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    (stdo1, stde1) = broker.communicate()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet2, timeout=20, port=port)

    mosq_test.expect_packet(sock, "publish2", publish_packet2)
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
        pass


exit(rc)

