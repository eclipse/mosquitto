#!/usr/bin/env python

# Test remapping of topic name for incoming message

import socket

import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

def write_config(filename, port1, port2, port3):
    with open(filename, 'w') as f:
        f.write("per_listener_settings true\n")
        f.write("port %d\n" % (port2))
        f.write("listener %d 127.0.0.1\n" % (port3))
        f.write("\n")
        f.write("connection bridge_sample\n")
        f.write("address 127.0.0.1:%d\n" % (port1))
        f.write("bridge_attempt_unsubscribe false\n")
        f.write("topic # in 0 local/topic/ remote/topic/\n")
        f.write("topic prefix/# in 0 local2/topic/ remote2/topic/\n")
        f.write("topic +/value in 0 local3/topic/ remote3/topic/\n")
        f.write("topic ic/+ in 0 local4/top remote4/tip\n")
        f.write("topic clients/total in 0 test/mosquitto/org $SYS/broker/\n")
        f.write("notifications false\n")
        f.write("restart_timeout 5\n")

(port1, port2, port3) = mosq_test.get_port(3)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port1, port2, port3)

rc = 1
keepalive = 60
client_id = socket.gethostname()+".bridge_sample"
connect_packet = mosq_test.gen_connect(client_id, keepalive=keepalive, clean_session=False, proto_ver=128+4)
connack_packet = mosq_test.gen_connack(rc=0)

client_connect_packet = mosq_test.gen_connect("pub-test", keepalive=keepalive)
client_connack_packet = mosq_test.gen_connack(rc=0)

ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ssock.settimeout(4)
ssock.bind(('', port1))
ssock.listen(5)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)


def test(bridge, sock):
    if not mosq_test.expect_packet(bridge, "connect", connect_packet):
        return 1
    bridge.send(connack_packet)

    mid = 0
    patterns = [
        "remote/topic/#",
        "remote2/topic/prefix/#",
        "remote3/topic/+/value",
        "remote4/tipic/+",
        "$SYS/broker/clients/total",
    ]
    for pattern in ("remote/topic/#", "remote2/topic/prefix/#", "remote3/topic/+/value"):
        mid += 1
        subscribe_packet = mosq_test.gen_subscribe(mid, pattern, 0)
        suback_packet = mosq_test.gen_suback(mid, 0)
        if not mosq_test.expect_packet(bridge, "subscribe", subscribe_packet):
            return 1
        bridge.send(suback_packet)

    mid += 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "#", 0)
    suback_packet = mosq_test.gen_suback(mid, 0)
    sock.send(subscribe_packet)
    if not mosq_test.expect_packet(sock, "suback", suback_packet):
        return 1

    cases = [
        ('local/topic/something', 'remote/topic/something'),
        ('local/topic/some/t/h/i/n/g', 'remote/topic/some/t/h/i/n/g'),
        ('local/topic/value', 'remote/topic/value'),
        # Don't work, #40 must be fixed before
        # ('local/topic', 'remote/topic'),
        ('local2/topic/prefix/something', 'remote2/topic/prefix/something'),
        ('local3/topic/something/value', 'remote3/topic/something/value'),
        ('local4/topic/something', 'remote4/tipic/something'),
        ('test/mosquitto/orgclients/total', '$SYS/broker/clients/total'),
    ]

    for (local_topic, remote_topic) in cases:
        mid += 1
        remote_publish_packet = mosq_test.gen_publish(
            remote_topic, qos=0, mid=mid, payload=''
        )
        local_publish_packet = mosq_test.gen_publish(
            local_topic, qos=0, mid=mid, payload=''
        )

        bridge.send(remote_publish_packet)
        match = mosq_test.expect_packet(sock, "publish", local_publish_packet)
        if not match:
            print("Fail on cases local_topic=%r, remote_topic=%r" % (
                local_topic, remote_topic,
            ))
            return 1
    return 0

try:
    (bridge, address) = ssock.accept()
    bridge.settimeout(2)

    sock = mosq_test.do_client_connect(
        client_connect_packet, client_connack_packet,
        port=port2,
    )

    rc = test(bridge, sock)

    sock.close()
    bridge.close()
finally:
    os.remove(conf_file)
    try:
        bridge.close()
    except NameError:
        pass

    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde)
    ssock.close()

exit(rc)
