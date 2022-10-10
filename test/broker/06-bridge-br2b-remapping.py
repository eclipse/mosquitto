#!/usr/bin/env python3

# Test remapping of topic name for outgoing message

from mosq_test_helper import *

def write_config(filename, port1, port2, protocol_version):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("connection bridge_sample\n")
        f.write("address 127.0.0.1:%d\n" % (port1))
        f.write("bridge_attempt_unsubscribe false\n")
        f.write("topic # out 0 local/topic/ remote/topic/\n")
        f.write("topic prefix/# out 0 local2/topic/ remote2/topic/\n")
        f.write("topic +/value out 0 local3/topic/ remote3/topic/\n")
        f.write("topic ic/+ out 0 local4/top remote4/tip\n")
        f.write("notifications false\n")
        f.write("restart_timeout 5\n")
        f.write("bridge_protocol_version %s\n" % (protocol_version))
        f.write("bridge_max_topic_alias 0\n")


def inner_test(bridge, sock, proto_ver):
    global connect_packet, connack_packet

    if not mosq_test.expect_packet(bridge, "connect", connect_packet):
        return 1

    bridge.send(connack_packet)

    cases = [
        ('local/topic/something', 'remote/topic/something'),
        ('local/topic/some/t/h/i/n/g', 'remote/topic/some/t/h/i/n/g'),
        ('local/topic/value', 'remote/topic/value'),
        # Don't work, #40 must be fixed before
        # ('local/topic', 'remote/topic'),
        ('local2/topic/something', None),  # don't match topic pattern
        ('local2/topic/prefix/something', 'remote2/topic/prefix/something'),
        ('local3/topic/something/value', 'remote3/topic/something/value'),
        ('local4/topic/something', 'remote4/tipic/something'),
        ('local5/topic/something', None),
    ]

    mid = 3
    for (local_topic, remote_topic) in cases:
        mid += 1
        local_publish_packet = mosq_test.gen_publish(
            local_topic, qos=0, mid=mid, payload='', proto_ver=proto_ver
        )
        sock.send(local_publish_packet)
        if remote_topic:
            remote_publish_packet = mosq_test.gen_publish(
                remote_topic, qos=0, mid=mid, payload='', proto_ver=proto_ver
            )
            match = mosq_test.expect_packet(bridge, "publish", remote_publish_packet)
            if not match:
                print("Fail on cases local_topic=%r, remote_topic=%r" % (
                    local_topic, remote_topic,
                ))
                return 1
        else:
            time.sleep(1)
            mosq_test.do_ping(bridge,
                "FAIL: Received data when nothing is expected\nFail on cases local_topic=%r, remote_topic=%r" % (
                local_topic, remote_topic,
                ))
    return 0


def do_test(proto_ver):
    global connect_packet, connack_packet

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
    connect_packet = mosq_test.gen_connect(client_id, clean_session=False, proto_ver=proto_ver_connect)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    client_connect_packet = mosq_test.gen_connect("pub-test", proto_ver=proto_ver)
    client_connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssock.settimeout(4)
    ssock.bind(('', port1))
    ssock.listen(5)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

    try:
        (bridge, address) = ssock.accept()
        bridge.settimeout(2)

        sock = mosq_test.do_client_connect(
            client_connect_packet, client_connack_packet,
            port=port2,
        )

        rc = inner_test(bridge, sock, proto_ver)

        sock.close()
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


do_test(proto_ver=4)
do_test(proto_ver=5)

exit(0)
