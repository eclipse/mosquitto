#!/usr/bin/env python3

# Does a cleansession bridge still send QoS 1 messages after reconnecting with
# a full inflight window? The discarded inflight messages must not keep
# holding on to the inflight quota.

from mosq_test_helper import *

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])

def write_config(filename, port1, port2, protocol_version):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")
        f.write("max_inflight_messages 2\n")
        f.write("\n")
        f.write("connection bridge_sample\n")
        f.write("address localhost:%d\n" % (port1))
        f.write("topic bridge/# both 1\n")
        f.write("cleansession true\n")
        f.write("notifications false\n")
        f.write("restart_timeout 2\n")
        f.write("bridge_protocol_version %s\n" % (protocol_version))
        f.write("bridge_max_topic_alias 0\n")


def do_test(proto_ver):
    if proto_ver == 4:
        bridge_protocol = "mqttv311"
        proto_ver_connect = 128+4
        props = b""
    else:
        bridge_protocol = "mqttv50"
        proto_ver_connect = 5
        props = mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 2)

    (port1, port2) = mosq_test.get_port(2)
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port1, port2, bridge_protocol)

    rc = 1
    client_id = socket.gethostname()+".bridge_sample"
    connect_packet = mqtt_packets.gen_connect(client_id, clean_session=True, proto_ver=proto_ver_connect, properties=props)
    # No receive-maximum in the CONNACK, a changed value would reset the quota and hide the leak
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver, property_helper=False)

    if proto_ver == 5:
        opts = mqtt5_opts.MQTT_SUB_OPT_NO_LOCAL | mqtt5_opts.MQTT_SUB_OPT_RETAIN_AS_PUBLISHED
    else:
        opts = 0

    subscribe_packet = mqtt_packets.gen_subscribe(1, "bridge/#", 1 | opts, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(1, 1, proto_ver=proto_ver)

    publish1_packet = mqtt_packets.gen_publish("bridge/test/1", qos=1, mid=2, payload="message1", proto_ver=proto_ver)
    publish2_packet = mqtt_packets.gen_publish("bridge/test/2", qos=1, mid=3, payload="message2", proto_ver=proto_ver)

    subscribe2_packet = mqtt_packets.gen_subscribe(4, "bridge/#", 1 | opts, proto_ver=proto_ver)
    suback2_packet = mqtt_packets.gen_suback(4, 1, proto_ver=proto_ver)

    publish3_packet = mqtt_packets.gen_publish("bridge/test/3", qos=1, mid=5, payload="message3", proto_ver=proto_ver)
    puback3_packet = mqtt_packets.gen_puback(5, proto_ver=proto_ver)

    helper_connect_packet = mqtt_packets.gen_connect("test-helper", proto_ver=4)
    helper_connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=4)
    helper_publish1_packet = mqtt_packets.gen_publish("bridge/test/1", qos=1, mid=1, payload="message1", proto_ver=4)
    helper_puback1_packet = mqtt_packets.gen_puback(1, proto_ver=4)
    helper_publish2_packet = mqtt_packets.gen_publish("bridge/test/2", qos=1, mid=2, payload="message2", proto_ver=4)
    helper_puback2_packet = mqtt_packets.gen_puback(2, proto_ver=4)
    helper_publish3_packet = mqtt_packets.gen_publish("bridge/test/3", qos=1, mid=3, payload="message3", proto_ver=4)
    helper_puback3_packet = mqtt_packets.gen_puback(3, proto_ver=4)

    ssock = mosq_test.listen_sock(port1)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

    try:
        (bridge, address) = ssock.accept()
        bridge.settimeout(20)

        mosq_test.expect_packet(bridge, "connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "subscribe", subscribe_packet)
        bridge.send(suback_packet)

        helper_sock = mosq_test.do_client_connect(helper_connect_packet, helper_connack_packet, port=port2, connack_error="helper connack")
        mosq_test.do_send_receive(helper_sock, helper_publish1_packet, helper_puback1_packet, "helper puback1")
        mosq_test.do_send_receive(helper_sock, helper_publish2_packet, helper_puback2_packet, "helper puback2")

        # Never acknowledged, so the inflight window is full when the bridge drops
        mosq_test.expect_packet(bridge, "publish1", publish1_packet)
        mosq_test.expect_packet(bridge, "publish2", publish2_packet)
        bridge.close()

        (bridge, address) = ssock.accept()
        bridge.settimeout(20)

        mosq_test.expect_packet(bridge, "2nd connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "2nd subscribe", subscribe2_packet)
        bridge.send(suback2_packet)

        mosq_test.do_send_receive(helper_sock, helper_publish3_packet, helper_puback3_packet, "helper puback3")
        helper_sock.close()

        mosq_test.expect_packet(bridge, "publish3", publish3_packet)
        bridge.send(puback3_packet)
        rc = 0

        bridge.close()
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        try:
            bridge.close()
        except NameError:
            pass

        mosq_test.terminate_broker(broker)
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        ssock.close()
        if rc:
            print(mosq_test.broker_log(broker))
            exit(rc)


do_test(proto_ver=4)
do_test(proto_ver=5)

exit(0)
