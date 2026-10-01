#!/usr/bin/env python3

# Test whether a client can connect over a socket provided by the application
# with mosquitto_connect_transport().

# The client should open a TCP connection to the test port itself and hand it
# over in its transport open callback, then connect with keepalive=60, clean
# session set, and client id 01-connect-transport.
# The test will send a CONNACK message to the client with rc=0. Upon receiving
# the CONNACK and verifying that rc=0, the client should send a DISCONNECT
# message.
# The client then does the whole thing a second time, over a socket newly
# provided by its transport open callback, which it only does once it has
# checked that the first socket was handed back to its transport close
# callback. A missing or wrong close callback therefore shows up here as a
# missing second connection.
# It connects a third time and then destroys the instance while still
# connected, without disconnecting, to check that the socket is handed back on
# that path as well.

from mosq_test_helper import *

def do_test():
    port = mosq_test.get_port()
    sock = mosq_test.listen_sock(port)

    connect_packet = mqtt_packets.gen_connect("01-connect-transport")
    connack_packet = mqtt_packets.gen_connack(rc=0)
    disconnect_packet = mqtt_packets.gen_disconnect()

    client_path = Path(mosq_test.get_build_root(), "test", "lib", "c",
            mosq_test.get_build_type(), "01-connect-transport.exe")
    client = mosq_test.start_client(filename="c-01-connect-transport",
            cmd=[str(client_path), str(port)])

    rc = 1
    try:
        for attempt in ("first", "second"):
            (conn, address) = sock.accept()
            conn.settimeout(10)
            mosq_test.do_receive_send(conn, connect_packet, connack_packet,
                    f"connect ({attempt})")
            mosq_test.expect_packet(conn, f"disconnect ({attempt})",
                    disconnect_packet)
            conn.close()

        # Third connection: the client destroys the instance while still
        # connected, so it sends no DISCONNECT.
        (conn, address) = sock.accept()
        conn.settimeout(10)
        mosq_test.do_receive_send(conn, connect_packet, connack_packet,
                "connect (third)")
        conn.close()
        rc = 0
    except mosq_test.TestError as err:
        print(err)
    except Exception as err:
        print(err)
        raise
    finally:
        if mosq_test.wait_for_subprocess(client):
            print("test client not finished")
            rc = 1
        # client_test() does not look at this, but the client checks its
        # callbacks itself and reports through its exit status.
        if client.returncode != 0:
            print(f"client exited with {client.returncode}")
            rc = 1
        sock.close()
        if rc:
            (o, e) = client.communicate()
            print(o)
            print(e)
            print(f"Fail: 01-connect-transport rc={rc}")
            exit(rc)

do_test()
