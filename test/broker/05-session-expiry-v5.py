#!/usr/bin/env python3

# MQTT v5. Test whether session expiry interval works correctly.

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1

    # This client exists to test possible fixed size int overflow and sorting of the session intervals
    # https://github.com/eclipse/mosquitto/issues/1525
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 4294967294)
    connect0_packet = mosq_test.gen_connect("05-session-expiry-overflow", clean_session=False, proto_ver=5, properties=props)
    connack0_packet = mosq_test.gen_connack(flags=0, rc=0, proto_ver=5)


    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 1)
    connect_packet = mosq_test.gen_connect("05-session-expiry", clean_session=False, proto_ver=5, properties=props)
    connack1_packet = mosq_test.gen_connack(flags=0, rc=0, proto_ver=5)

    connack2_packet = mosq_test.gen_connack(flags=1, rc=0, proto_ver=5)

    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 3)
    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5, properties=props)

    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 0)
    disconnect2_packet = mosq_test.gen_disconnect(proto_ver=5, properties=props)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        # Connect client with wildly different session expiry, this should impact
        # on the test if all is well
        sock0 = mosq_test.do_client_connect(connect0_packet, connack0_packet, port=port, connack_error="connack 0")
        # Immediately disconnect, this should now be queued to expire
        sock0.close()

        # First connect, clean start is false, we expect a normal connack
        sock = mosq_test.do_client_connect(connect_packet, connack1_packet, port=port, connack_error="connack 1")
        # Forceful disconnect
        sock.close()

        # Immediate second connect, clean start is false, we expect a connack with
        # previous state
        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, port=port, connack_error="connack 2")
        sock.close()

        # Session should expire in one second, so sleep longer
        time.sleep(2)

        # Third connect, clean start is false, session should have expired so we
        # expect a normal connack
        sock = mosq_test.do_client_connect(connect_packet, connack1_packet, port=port, connack_error="connack 3")
        # Send DISCONNECT with new session expiry, then close
        sock.send(disconnect_packet)
        sock.close()

        # Immediate reconnect, clean start is false, we expect a connack with
        # previous state
        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, port=port, connack_error="connack 4")
        # Send DISCONNECT with new session expiry, then close
        sock.send(disconnect_packet)
        sock.close()

        # Session should expire in three seconds if it has been updated, sleep for
        # 2 to check it is updated from 1 second.
        time.sleep(2)

        # Immediate reconnect, clean start is false, we expect a connack with
        # previous state
        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, port=port, connack_error="connack 5")
        # Send DISCONNECT with new session expiry, then close
        sock.send(disconnect_packet)
        sock.close()

        # Session should expire in three seconds, so sleep longer
        time.sleep(4)
        # Third connect, clean start is false, session should have expired so we
        # expect a normal connack
        sock = mosq_test.do_client_connect(connect_packet, connack1_packet, port=port, connack_error="connack 6")
        # Send DISCONNECT with 0 session expiry, then close
        sock.send(disconnect2_packet)
        sock.close()

        # Immediate reconnect, session should have been removed.
        sock = mosq_test.do_client_connect(connect_packet, connack1_packet, port=port, connack_error="connack 7")
        sock.close()
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
    return do_test(start_broker)

if __name__ == '__main__':
    all_tests(True)
