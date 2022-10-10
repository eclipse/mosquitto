#!/usr/bin/env python3

# No local option is not allowed on shared subscriptions

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1
    mid = 1

    connect1_packet = mosq_test.gen_connect("02-shared-nolocal-client1", proto_ver=5)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    subscribe_packet = mosq_test.gen_subscribe(mid, "$share/sharename/subpub/qos1", 1 | mqtt5_opts.MQTT_SUB_OPT_NO_LOCAL, proto_ver=5)
    disconnect_packet = mosq_test.gen_disconnect(reason_code=mqtt5_rc.MQTT_RC_PROTOCOL_ERROR, proto_ver=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, disconnect_packet, "disconnect")
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
        else:
            return rc

def all_tests(start_broker=False):
    return do_test(start_broker)

if __name__ == '__main__':
    all_tests(True)
