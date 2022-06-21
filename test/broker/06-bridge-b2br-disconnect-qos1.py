#!/usr/bin/env python3

# Does a bridge resend a QoS=1 message correctly after a disconnect?

from mosq_test_helper import *

def write_config(filename, port1, port2, protocol_version):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("\n")
        f.write("connection bridge_sample\n")
        f.write("address 127.0.0.1:%d\n" % (port1))
        f.write("topic bridge/# both 1\n")
        f.write("notifications false\n")
        f.write("restart_timeout 5\n")
        f.write("bridge_protocol_version %s\n" % (protocol_version))


def do_test(proto_ver):
    if proto_ver == 4:
        bridge_protocol = "mqttv311"
        proto_ver_connect = 128+4
    else:
        bridge_protocol = "mqttv50"
        proto_ver_connect = 5

    (port1, port2) = mosq_test.get_port(2)
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port1, port2, bridge_protocol)

    rc = 1
    client_id = socket.gethostname()+".bridge_sample"
    properties = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS_MAXIMUM, 10)
    properties += mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_RECEIVE_MAXIMUM, 20)
    connect_packet = mosq_test.gen_connect(client_id, clean_session=False, proto_ver=proto_ver_connect, properties=properties)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    if proto_ver == 5:
        opts = mqtt5_opts.MQTT_SUB_OPT_NO_LOCAL | mqtt5_opts.MQTT_SUB_OPT_RETAIN_AS_PUBLISHED
    else:
        opts = 0

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "bridge/#", 1 | opts, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 1, proto_ver=proto_ver)

    mid = 2
    subscribe2_packet = mosq_test.gen_subscribe(mid, "bridge/#", 1 | opts, proto_ver=proto_ver)
    suback2_packet = mosq_test.gen_suback(mid, 1, proto_ver=proto_ver)

    mid = 3
    publish_packet = mosq_test.gen_publish("bridge/disconnect/test", qos=1, mid=mid, payload="disconnect-message", proto_ver=proto_ver)
    publish_dup_packet = mosq_test.gen_publish("bridge/disconnect/test", qos=1, mid=mid, payload="disconnect-message", dup=True, proto_ver=proto_ver)
    puback_packet = mosq_test.gen_puback(mid, proto_ver=proto_ver)

    mid = 20
    publish2_packet = mosq_test.gen_publish("bridge/disconnect/test", qos=1, mid=mid, payload="disconnect-message", proto_ver=proto_ver)
    puback2_packet = mosq_test.gen_puback(mid, proto_ver=proto_ver)

    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssock.settimeout(40)
    ssock.bind(('', port1))
    ssock.listen(5)

    try:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

        (bridge, address) = ssock.accept()
        bridge.settimeout(20)

        mosq_test.expect_packet(bridge, "connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "subscribe", subscribe_packet)
        bridge.send(suback_packet)

        bridge.send(publish_packet)
        # Bridge doesn't have time to respond but should expect us to retry
        # and so remove PUBACK.
        bridge.close()

        (bridge, address) = ssock.accept()
        bridge.settimeout(20)

        mosq_test.expect_packet(bridge, "2nd connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "2nd subscribe", subscribe2_packet)
        bridge.send(suback2_packet)

        # Send a different publish message to make sure the response isn't to the old one.
        bridge.send(publish2_packet)
        mosq_test.expect_packet(bridge, "puback", puback2_packet)
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

        broker.terminate()
        broker.wait()
        (stdo, stde) = broker.communicate()
        ssock.close()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)

do_test(proto_ver=4)
do_test(proto_ver=5)

exit(0)
