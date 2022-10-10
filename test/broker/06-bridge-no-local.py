#!/usr/bin/env python3

# Check whether an incoming bridge connection receives its own messages. It
# shouldn't because for v3.1 and v3.1.1 we have no-local set for all bridges.

from mosq_test_helper import *

def do_test(start_broker, proto_ver_connect, proto_ver_msgs, sub_opts):
    rc = 1
    connect_packet = mosq_test.gen_connect("bridge-test", proto_ver=proto_ver_connect)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver_msgs)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "loop/test", 0 | sub_opts, proto_ver=proto_ver_msgs)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver_msgs)

    publish_packet = mosq_test.gen_publish("loop/test", qos=0, payload="message", proto_ver=proto_ver_msgs)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock.send(publish_packet)
        mosq_test.do_ping(sock)
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
                exit(rc)
        else:
            return rc


def all_tests(start_broker=False):
    rc = do_test(start_broker, 128+3, 3, 0)
    if rc:
        return rc;
    rc = do_test(start_broker, 128+4, 4, 0)
    if rc:
        return rc;
    rc = do_test(start_broker, 5, 5, mqtt5_opts.MQTT_SUB_OPT_NO_LOCAL)
    if rc:
        return rc;
    return 0

if __name__ == '__main__':
    all_tests(True)
