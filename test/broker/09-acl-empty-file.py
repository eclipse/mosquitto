#!/usr/bin/env python3

# Test for CVE-2018-xxxxx

from mosq_test_helper import *
import signal

def write_config(filename, port, per_listener):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener))
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("acl_file %s\n" % (filename.replace('.conf', '.acl')))

def write_acl(filename):
    with open(filename, 'w') as f:
        f.write('#comment\n')
        f.write('\n')


def do_test(port, per_listener):
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, per_listener)

    acl_file = os.path.basename(__file__).replace('.py', '.acl')
    write_acl(acl_file)

    rc = 1
    connect_packet = mosq_test.gen_connect("acl-check")
    connack_packet = mosq_test.gen_connack(rc=0)

    mid = 1
    publish_packet = mosq_test.gen_publish("test/topic", qos=0, payload="message")
    subscribe_packet = mosq_test.gen_subscribe(mid, "test/topic", 0)
    suback_packet = mosq_test.gen_suback(mid, 0)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock.send(publish_packet)

        # If we receive the message, this will fail.
        mosq_test.do_ping(sock)
        rc = 0

        sock.close()
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
do_test(port, "false")
do_test(port, "true")
