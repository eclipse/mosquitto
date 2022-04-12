#!/usr/bin/env python3

# Check whether messages deliver or not after some access is revoked.

from mosq_test_helper import *
import signal

def write_config(filename, port, per_listener):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener))
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("acl_file %s\n" % (filename.replace('.conf', '.acl')))

def write_acl(filename, en):
    with open(filename, 'w') as f:
        f.write('user username\n')
        f.write('topic readwrite topic/one\n')
        if en:
            f.write('topic readwrite topic/two\n')

username = "username"

connect1_packet = mosq_test.gen_connect("acl-check", username=username, clean_session=False)
connack1a_packet = mosq_test.gen_connack(rc=0)
connack1b_packet = mosq_test.gen_connack(rc=0, flags=1)

mid = 1
subscribe1_packet = mosq_test.gen_subscribe(mid=mid, topic="topic/one", qos=1)
suback1_packet = mosq_test.gen_suback(mid=mid, qos=1)

mid = 2
subscribe2_packet = mosq_test.gen_subscribe(mid=mid, topic="topic/two", qos=1)
suback2_packet = mosq_test.gen_suback(mid=mid, qos=1)

disconnect_packet = mosq_test.gen_disconnect()

connect2_packet = mosq_test.gen_connect("helper", username=username)
connack2_packet = mosq_test.gen_connack(rc=0)

mid = 1
publish1s_packet = mosq_test.gen_publish(topic="topic/one", mid=mid, qos=1, payload="message1")
puback1s_packet = mosq_test.gen_puback(mid)

mid = 2
publish2s_packet = mosq_test.gen_publish(topic="topic/two", mid=mid, qos=1, payload="message2")
puback2s_packet = mosq_test.gen_puback(mid)

mid = 1
publish1r_packet = mosq_test.gen_publish(topic="topic/one", mid=mid, qos=1, payload="message1")
puback1r_packet = mosq_test.gen_puback(mid)

mid = 2
publish3s_packet = mosq_test.gen_publish(topic="topic/one", mid=mid, qos=1, payload="message3")
puback3s_packet = mosq_test.gen_puback(mid)

mid = 3
publish3r_packet = mosq_test.gen_publish(topic="topic/one", mid=mid, qos=1, payload="message3")
puback3r_packet = mosq_test.gen_puback(mid)

mid = 3
publish4s_packet = mosq_test.gen_publish(topic="topic/two", mid=mid, qos=1, payload="message4")
puback4s_packet = mosq_test.gen_puback(mid)

rc = 1

port = mosq_test.get_port()

conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port, "false")

acl_file = os.path.basename(__file__).replace('.py', '.acl')
write_acl(acl_file, True)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    # Connect, subscribe, then disconnect
    sock = mosq_test.do_client_connect(connect1_packet, connack1a_packet, port=port)
    mosq_test.do_send_receive(sock, subscribe1_packet, suback1_packet, "suback1")
    mosq_test.do_send_receive(sock, subscribe2_packet, suback2_packet, "suback2")
    sock.send(disconnect_packet)
    sock.close()

    # Helper publish to topic/one and topic/two, will be queued for other client
    sock = mosq_test.do_client_connect(connect2_packet, connack2_packet, port=port)
    mosq_test.do_send_receive(sock, publish1s_packet, puback1s_packet, "puback1")
    mosq_test.do_send_receive(sock, publish2s_packet, puback2s_packet, "puback2")
    sock.close()

    # Reload ACLs with topic/two now disabled
    write_acl(acl_file, False)
    broker.send_signal(signal.SIGHUP)

    sock = mosq_test.do_client_connect(connect1_packet, connack1b_packet, port=port)
    sock.settimeout(10)
    mosq_test.expect_packet(sock, "publish1r", publish1r_packet)
    # We don't expect messages to topic/two any more, so we don't expect the queued one
    sock.send(publish3s_packet)
    mosq_test.receive_unordered(sock, puback3s_packet, publish3r_packet, "puback3/publish3r")

    # Send this, don't expect it to succeed
    mosq_test.do_send_receive(sock, publish4s_packet, puback4s_packet, "puback4")

    # Check for non delivery with a ping
    mosq_test.do_ping(sock)

    sock.close()
    rc = 0

except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    os.remove(acl_file)
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))
        exit(rc)

port = mosq_test.get_port()

