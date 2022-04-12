#!/usr/bin/env python3

# Test whether sending a non zero session expiry interval in DISCONNECT after
# having sent a zero session expiry interval is treated correctly in MQTT v5.

from mosq_test_helper import *


def do_test(start_broker, clean_start):
    rc = 1
    connect_packet = mosq_test.gen_connect(None, proto_ver=5, clean_session=clean_start)

    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_ASSIGNED_CLIENT_IDENTIFIER, "auto-00000000-0000-0000-0000-000000000000")
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props)

    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 1)
    disconnect_client_packet = mosq_test.gen_disconnect(proto_ver=5, properties=props)

    disconnect_server_packet = mosq_test.gen_disconnect(proto_ver=5, reason_code=130)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("localhost", port))

        sock.send(connect_packet)
        connack_recvd = sock.recv(len(connack_packet))

        if connack_recvd[0:12] == connack_packet[0:12]:
            # FIXME - this test could be tightened up a lot
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
    rc = do_test(start_broker, True)
    if rc:
        return rc;
    rc = do_test(start_broker, False)
    if rc:
        return rc;
    return 0

if __name__ == '__main__':
    all_tests(True)
