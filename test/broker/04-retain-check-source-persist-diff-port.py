#!/usr/bin/env python3

# Test for CVE-2018-12546, with the broker being stopped to write the persistence file, plus subscriber on different port.

from mosq_test_helper import *
import os.path
import signal

def write_config(filename, port1, port2, per_listener):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener))
        f.write("check_retain_source true\n")
        f.write("listener %d\n" % (port1))
        f.write("allow_anonymous true\n")
        f.write("acl_file %s\n" % (filename.replace('.conf', '.acl')))
        f.write("persistence true\n")
        f.write("persistence_file %s\n" % (filename.replace('.conf', '.db')))
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")

def write_acl_1(filename, username):
    with open(filename, 'w') as f:
        if username is not None:
            f.write('user %s\n' % (username))
        f.write('topic readwrite test/topic\n')

def write_acl_2(filename, username):
    with open(filename, 'w') as f:
        if username is not None:
            f.write('user %s\n' % (username))
        f.write('topic read test/topic\n')


def do_test(proto_ver, per_listener, username):
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port1, port2, per_listener)

    persistence_file = os.path.basename(__file__).replace('.py', '.db')
    try:
        os.remove(persistence_file)
    except OSError:
        pass

    acl_file = os.path.basename(__file__).replace('.py', '.acl')
    write_acl_1(acl_file, username)


    rc = 1
    connect_packet = mosq_test.gen_connect("retain-check", username=username, proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    if per_listener == "true":
        u = None
    else:
        # If per listener is false, then the second client will be denied
        # unless we provide a username
        u = username

    connect2_packet = mosq_test.gen_connect("retain-recv", username=u, proto_ver=proto_ver)
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    publish_packet = mosq_test.gen_publish("test/topic", qos=0, payload="retained message", retain=True, proto_ver=proto_ver)
    subscribe_packet = mosq_test.gen_subscribe(mid, "test/topic", 0, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port1)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port1)
        sock.send(publish_packet)
        sock.close()

        sock = mosq_test.do_client_connect(connect2_packet, connack2_packet, port=port2)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback 1")

        mosq_test.expect_packet(sock, "publish", publish_packet)
        sock.close()

        # Remove "write" ability
        write_acl_2(acl_file, username)
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        if os.path.isfile(persistence_file) == False:
            raise FileNotFoundError("Persistence file not written")

        broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port1)

        sock = mosq_test.do_client_connect(connect2_packet, connack2_packet, port=port2)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback 2")
        # If we receive the retained message here, it is a failure.
        mosq_test.do_ping(sock)
        rc = 0

        sock.close()
    except mosq_test.TestError:
        pass
    finally:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        os.remove(conf_file)
        os.remove(acl_file)
        try:
            os.remove(persistence_file)
        except FileNotFoundError:
            pass
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)


(port1, port2) = mosq_test.get_port(2)
do_test(proto_ver=4, per_listener="true", username=None)
do_test(proto_ver=4, per_listener="true", username="test")
do_test(proto_ver=4, per_listener="false", username=None)
do_test(proto_ver=4, per_listener="false", username="test")

do_test(proto_ver=5, per_listener="true", username=None)
do_test(proto_ver=5, per_listener="true", username="test")
do_test(proto_ver=5, per_listener="false", username=None)
do_test(proto_ver=5, per_listener="false", username="test")
