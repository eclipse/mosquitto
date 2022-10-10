#!/usr/bin/env python3

# Test whether a bridge can cope with an unknown PUBACK

from mosq_test_helper import *

def write_config(filename, port1, port2, protocol_version):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("\n")
        f.write("connection bridge-u-test\n")
        f.write("remote_clientid bridge-u-test\n")
        f.write("address 127.0.0.1:%d\n" % (port1))
        f.write("topic bridge/# out\n")
        f.write("\n")
        f.write("cleansession true\n")
        f.write("notifications false\n")
        f.write("restart_timeout 5\n")
        f.write("try_private false\n")
        f.write("bridge_protocol_version %s\n" % (protocol_version))
        f.write("bridge_max_topic_alias 0\n")


def do_test(proto_ver):
    if proto_ver == 4:
        bridge_protocol = "mqttv311"
        proto_ver_connect = 4
    else:
        bridge_protocol = "mqttv50"
        proto_ver_connect = 5

    (port1, port2) = mosq_test.get_port(2)
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port1, port2, bridge_protocol)

    rc = 1
    connect_packet = mosq_test.gen_connect("bridge-u-test", proto_ver=proto_ver_connect)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 180
    mid_unknown = 2000

    publish_packet = mosq_test.gen_publish("bridge/unknown/qos2", qos=1, payload="bridge-message", mid=mid, proto_ver=proto_ver)
    puback_packet = mosq_test.gen_puback(mid, proto_ver=proto_ver)

    pubrec_packet_unknown1 = mosq_test.gen_pubrec(mid_unknown+1, proto_ver=proto_ver)
    pubrel_packet_unknown1 = mosq_test.gen_pubrel(mid_unknown+1, proto_ver=proto_ver)

    pubrel_packet_unknown2 = mosq_test.gen_pubrel(mid_unknown+2, proto_ver=proto_ver)
    pubcomp_packet_unknown2 = mosq_test.gen_pubcomp(mid_unknown+2, proto_ver=proto_ver)

    pubcomp_packet_unknown3 = mosq_test.gen_pubcomp(mid_unknown+3, proto_ver=proto_ver)


    unsubscribe_packet = mosq_test.gen_unsubscribe(1, "bridge/#", proto_ver=proto_ver)
    unsuback_packet = mosq_test.gen_unsuback(1, proto_ver=proto_ver)


    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        sleep_time = 5
    else:
        sleep_time = 0.5


    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(10)
    sock.bind(('', port1))
    sock.listen(5)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)
    time.sleep(sleep_time)

    try:
        (conn, address) = sock.accept()
        conn.settimeout(20)

        mosq_test.expect_packet(conn, "connect", connect_packet)
        conn.send(connack_packet)

        mosq_test.expect_packet(conn, "unsubscribe", unsubscribe_packet)
        conn.send(unsuback_packet)

        # Send the unexpected pubrec packet
        conn.send(pubrec_packet_unknown1)
        mosq_test.expect_packet(conn, "pubrel", pubrel_packet_unknown1)

        conn.send(pubrel_packet_unknown2)
        mosq_test.expect_packet(conn, "pubcomp", pubcomp_packet_unknown2)

        conn.send(pubcomp_packet_unknown3)

        # Send a legitimate publish packet to verify everything is still ok
        conn.send(publish_packet)

        mosq_test.expect_packet(conn, "puback", puback_packet)
        rc = 0

    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        sock.close()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)


do_test(proto_ver=4)
do_test(proto_ver=5)

exit(0)

