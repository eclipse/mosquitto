#!/usr/bin/env python3

# tests that bridge configuration is reloaded on signal

from mosq_test_helper import *
import signal


def write_config(filename, port1, port2, subtopic, reload_immediate=False):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("connection bridge_sample\n")
        f.write("address 127.0.0.1:%d\n" % (port1))
        f.write("topic # in 0 local/topic/ remote/%s/\n" % (subtopic))
        f.write("notifications false\n")
        f.write("restart_timeout 1\n")
        if reload_immediate:
            f.write("bridge_reload_type immediate\n")
        f.write("bridge_max_topic_alias 0\n")


def accept_new_connection(sock):
    conn, _ = sock.accept()
    conn.settimeout(20)

    client_id = socket.gethostname()+".bridge_sample"
    connect_packet = mosq_test.gen_connect(
        client_id, clean_session=False, proto_ver=0x84)
    connack_packet = mosq_test.gen_connack()

    mosq_test.expect_packet(conn, "connect", connect_packet)
    conn.send(connack_packet)

    return conn


def accept_subscription(socket, topic, mid=1, qos=0):
    subscribe_packet = mosq_test.gen_subscribe(mid, topic, qos)
    suback_packet = mosq_test.gen_suback(mid, qos)

    mosq_test.expect_packet(socket, "subscribe", subscribe_packet)
    socket.send(suback_packet)


def start_fake_broker(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(3)
    sock.bind(('', port))
    sock.listen(5)
    return sock


def expect_no_incoming_connection(sock):
    try:
        accept_new_connection(sock) # will timeout if nothing comes in
        raise mosq_test.TestError # hence, it shouldn't reach this
    except socket.timeout:
        pass


def do_test():
    rc = 1

    port1, port2 = mosq_test.get_port(2)
    conf_file = os.path.basename(__file__).replace('.py', '.conf')

    try:
        ssock = start_fake_broker(port1)

        write_config(conf_file, port1, port2, "topic1", True)

        broker = mosq_test.start_broker(
            filename=os.path.basename(__file__), port=port2, use_conf=True)

        bridge = accept_new_connection(ssock)
        accept_subscription(bridge, "remote/topic1/#")

        write_config(conf_file, port1, port2, "topic2", True)
        broker.send_signal(signal.SIGHUP)

        bridge = accept_new_connection(ssock) # immediate reload forces a reconnection
        accept_subscription(bridge, "remote/topic2/#")

        write_config(conf_file, port1, port2, "topic3", False)
        broker.send_signal(signal.SIGHUP)

        expect_no_incoming_connection(ssock) # as it was set to lazy reload

        bridge.close()

        bridge = accept_new_connection(ssock)
        accept_subscription(bridge, "remote/topic3/#")

        rc = 0

    except mosq_test.TestError:
        pass
    finally:
        try:
            broker.terminate()
            if mosq_test.wait_for_subprocess(broker):
                print("broker not terminated")
                if rc == 0: rc=1
            _, stde = broker.communicate()
            if rc:
                print(stde.decode('utf-8'))
        except NameError:
            pass

        try:
            os.remove(conf_file)
        except FileNotFoundError:
            pass

        try:
            bridge.close()
        except NameError:
            pass

        try:
            ssock.close()
        except NameError:
            pass

        return rc


exit_code = do_test()
exit(exit_code)
