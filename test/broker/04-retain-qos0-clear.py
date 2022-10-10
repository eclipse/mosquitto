#!/usr/bin/env python3

# Test whether a retained PUBLISH is cleared when a zero length retained
# message is published to a topic.

from mosq_test_helper import *


def do_test(start_broker, proto_ver):
    rc = 1
    connect_packet = mosq_test.gen_connect("retain-qos0-clear-test", proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    publish_packet = mosq_test.gen_publish("retain/qos0/clear/test", qos=0, payload="retained message", retain=True, proto_ver=proto_ver)
    retain_clear_packet = mosq_test.gen_publish("retain/qos0/clear/test", qos=0, payload=None, retain=True, proto_ver=proto_ver)
    mid_sub = 592
    subscribe_packet = mosq_test.gen_subscribe(mid_sub, "retain/qos0/clear/test", 0, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid_sub, 0, proto_ver=proto_ver)

    mid_unsub = 593
    unsubscribe_packet = mosq_test.gen_unsubscribe(mid_unsub, "retain/qos0/clear/test", proto_ver=proto_ver)
    unsuback_packet = mosq_test.gen_unsuback(mid_unsub, proto_ver=proto_ver)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=4, port=port)
        # Send retained message
        sock.send(publish_packet)
        # Subscribe to topic, we should get the retained message back.
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        mosq_test.expect_packet(sock, "publish", publish_packet)
        # Now unsubscribe from the topic before we clear the retained
        # message.
        mosq_test.do_send_receive(sock, unsubscribe_packet, unsuback_packet, "unsuback")

        # Now clear the retained message.
        sock.send(retain_clear_packet)

        # Subscribe to topic, we shouldn't get anything back apart
        # from the SUBACK.
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        # If we do get something back, it should be before this ping, so if
        # this succeeds then we're ok.
        mosq_test.do_ping(sock)
        # This is the expected event
        rc = 0

        sock.close()
    except mosq_test.TestError:
        pass
    finally:
        if start_broker:
            broker.terminate()
            if mosq_test.wait_for_subprocess(broker):
                print("broker not terminated")
                if rc == 0: rc=1
            (stdo, stde) = broker.communicate()
            if rc:
                print(stde.decode('utf-8'))
                print("proto_ver=%d" % (proto_ver))
                exit(rc)
        else:
            return rc


def all_tests(start_broker=False):
    rc = do_test(start_broker, proto_ver=4)
    if rc:
        return rc;
    rc = do_test(start_broker, proto_ver=5)
    if rc:
        return rc;
    return 0

if __name__ == '__main__':
    all_tests(True)
