#!/usr/bin/env python3

# Does a bridge queue up retained messages correctly if the remote broker starts up late?

from mosq_test_helper import *

def write_config1(filename, persistence_file, port1, port2):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("persistence true\n")
        f.write("persistence_file %s\n" % (persistence_file))

def write_config2(filename, persistence_file, port1, port2, protocol_version):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("connection bridge_sample\n")
        f.write("address 127.0.0.1:%d\n" % (port1))
        f.write("topic bridge/# out 1\n")
        f.write("notifications false\n")
        f.write("bridge_attempt_unsubscribe false\n")
        f.write("bridge_protocol_version %s\n" % (protocol_version))
        f.write("bridge_max_topic_alias 0\n")
        f.write("persistence true\n")
        f.write("persistence_file %s\n" % (persistence_file))

def do_test(proto_ver):
    if proto_ver == 4:
        bridge_protocol = "mqttv311"
        proto_ver_connect = 128+4
    else:
        bridge_protocol = "mqttv50"
        proto_ver_connect = 5

    (port1, port2) = mosq_test.get_port(2)
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    persistence_file = os.path.basename(__file__).replace('.py', '.db')

    rc = 1
    client_id = socket.gethostname()+".bridge_sample"
    connect_packet = mosq_test.gen_connect(client_id, clean_session=False, proto_ver=proto_ver_connect)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    c_connect_packet = mosq_test.gen_connect("client", proto_ver=proto_ver)
    c_connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    publish_packet = mosq_test.gen_publish("bridge/test", qos=1, mid=mid, payload="message", retain=True, proto_ver=proto_ver)

    if proto_ver == 5:
        puback_packet = mosq_test.gen_puback(mid, proto_ver=proto_ver, reason_code=16)
    else:
        puback_packet = mosq_test.gen_puback(mid, proto_ver=proto_ver)

    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssock.settimeout(40)
    ssock.bind(('', port1))
    ssock.listen(5)

    write_config1(conf_file, persistence_file, port1, port2)

    try:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)
        client = mosq_test.do_client_connect(c_connect_packet, c_connack_packet, timeout=20, port=port2)
        mosq_test.do_send_receive(client, publish_packet, puback_packet, "puback")
        client.close()

        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1

        # Restart, with retained message in place
        write_config2(conf_file, persistence_file, port1, port2, bridge_protocol)
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

        (bridge, address) = ssock.accept()
        bridge.settimeout(20)

        mosq_test.expect_packet(bridge, "connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "publish", publish_packet)
        bridge.send(puback_packet)
        # Guard against multiple retained messages of the same type by
        # sending a pingreq to give us something to expect back. If we get
        # a publish, it's a fail.
        mosq_test.do_ping(bridge)
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
        os.remove(persistence_file)
        ssock.close()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)


do_test(proto_ver=4)
do_test(proto_ver=5)

exit(0)
