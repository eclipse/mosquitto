#!/usr/bin/env python3

# Does a bridge with bridge_outgoing_retain set to false not set the retain bit
# on outgoing messages?

from mosq_test_helper import *

def write_config(filename, port1, port2, protocol_version, outgoing_retain):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("connection bridge_sample\n")
        f.write("address 127.0.0.1:%d\n" % (port1))
        f.write("topic bridge/# both 1\n")
        f.write("notifications false\n")
        f.write("restart_timeout 5\n")
        f.write("bridge_protocol_version %s\n" %(protocol_version))
        f.write("bridge_outgoing_retain %s\n" %(outgoing_retain))
        f.write("bridge_max_topic_alias 0\n")

def do_test(proto_ver, outgoing_retain):
    if proto_ver == 4:
        bridge_protocol = "mqttv311"
        proto_ver_connect = 128+4
    else:
        bridge_protocol = "mqttv50"
        proto_ver_connect = 5

    (port1, port2) = mosq_test.get_port(2)
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port1, port2, bridge_protocol, outgoing_retain)

    rc = 1
    client_id = socket.gethostname()+".bridge_sample"
    connect_packet = mosq_test.gen_connect(client_id, clean_session=False, proto_ver=proto_ver_connect)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    if proto_ver == 5:
        opts = mqtt5_opts.MQTT_SUB_OPT_NO_LOCAL | mqtt5_opts.MQTT_SUB_OPT_RETAIN_AS_PUBLISHED
    else:
        opts = 0

    subscribe_packet = mosq_test.gen_subscribe(mid, "bridge/#", 1 | opts, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 1, proto_ver=proto_ver)

    if outgoing_retain == "true":
        publish_packet = mosq_test.gen_publish("bridge/retain/test", qos=0, retain=True, payload="message", proto_ver=proto_ver)
    else:
        publish_packet = mosq_test.gen_publish("bridge/retain/test", qos=0, retain=False, payload="message", proto_ver=proto_ver)


    helper_connect_packet = mosq_test.gen_connect("helper", clean_session=True, proto_ver=proto_ver)
    helper_connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
    helper_publish_packet = mosq_test.gen_publish("bridge/retain/test", qos=0, retain=True, payload="message", proto_ver=proto_ver)


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

        # Broker is now connected to us on port1.
        # Connect our client to the broker on port2 and send a publish
        # message, which we will then receive by way of the bridge
        helper = mosq_test.do_client_connect(helper_connect_packet, helper_connack_packet, port=port2)
        helper.send(helper_publish_packet)
        helper.close()

        mosq_test.expect_packet(bridge, "publish", publish_packet)
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
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        ssock.close()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)

do_test(proto_ver=4, outgoing_retain="true")
do_test(proto_ver=4, outgoing_retain="false")
do_test(proto_ver=5, outgoing_retain="true")
do_test(proto_ver=5, outgoing_retain="false")

exit(0)
