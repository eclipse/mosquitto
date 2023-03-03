#!/usr/bin/env python3

# Check access

from mosq_test_helper import *

def write_config(filename, port, per_listener):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener))
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("acl_file %s\n" % (filename.replace('.conf', '.acl')))

def write_acl(filename, global_en, user_en, pattern_en):
    with open(filename, 'w') as f:
        if global_en:
            f.write('topic readwrite topic/global/#\n')
            f.write('topic deny      topic/global/except\n')
        if user_en:
            f.write('user username\n')
            f.write('topic readwrite topic/username/#\n')
            f.write('topic deny      topic/username/except\n')
        if pattern_en:
            f.write('pattern readwrite pattern/%u/#\n')
            f.write('pattern deny      pattern/%u/except\n')



def single_test(port, per_listener, username, topic, expect_deny):
    connect_packet = mosq_test.gen_connect("acl-check", username=username)
    connack_packet = mosq_test.gen_connack(rc=0)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid=mid, topic=topic, qos=1)
    suback_packet = mosq_test.gen_suback(mid=mid, qos=1)

    mid = 2
    publish1s_packet = mosq_test.gen_publish(topic=topic, mid=mid, qos=1, payload="message")
    puback1s_packet = mosq_test.gen_puback(mid)

    mid=1
    publish1r_packet = mosq_test.gen_publish(topic=topic, mid=mid, qos=1, payload="message")

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
    sock.send(publish1s_packet)
    if expect_deny:
        mosq_test.expect_packet(sock, "puback", puback1s_packet)
        mosq_test.do_ping(sock)
    else:
        mosq_test.receive_unordered(sock, puback1s_packet, publish1r_packet, "puback / publish1r")
    sock.close()


def acl_test(port, per_listener, global_en, user_en, pattern_en):
    acl_file = os.path.basename(__file__).replace('.py', '.acl')
    conf_file = os.path.basename(__file__).replace('.py', '.conf')

    write_acl(acl_file, global_en=global_en, user_en=user_en, pattern_en=pattern_en)
    write_config(conf_file, port, per_listener)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    rc = 0
    try:
        if global_en:
            single_test(port, per_listener, username=None,       topic="topic/global", expect_deny=False)
            single_test(port, per_listener, username="username", topic="topic/global", expect_deny=True)
            single_test(port, per_listener, username=None,       topic="topic/global/except", expect_deny=True)
        if user_en:
            single_test(port, per_listener, username=None,       topic="topic/username", expect_deny=True)
            single_test(port, per_listener, username="username", topic="topic/username", expect_deny=False)
            single_test(port, per_listener, username="username", topic="topic/username/except", expect_deny=True)
        if pattern_en:
            single_test(port, per_listener, username=None,       topic="pattern/username", expect_deny=True)
            single_test(port, per_listener, username="username", topic="pattern/username", expect_deny=False)
            single_test(port, per_listener, username="username", topic="pattern/username/except", expect_deny=True)
    except mosq_test.TestError:
        rc = 1
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

def do_test(port, per_listener):
    acl_test(port, per_listener, global_en=False, user_en=False, pattern_en=True)
    acl_test(port, per_listener, global_en=False, user_en=True, pattern_en=False)
    acl_test(port, per_listener, global_en=True, user_en=False, pattern_en=False)
    acl_test(port, per_listener, global_en=False, user_en=True, pattern_en=True)
    acl_test(port, per_listener, global_en=True, user_en=False, pattern_en=True)
    acl_test(port, per_listener, global_en=True, user_en=True, pattern_en=True)

port = mosq_test.get_port()

do_test(port, "true")
do_test(port, "false")
