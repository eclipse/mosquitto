#!/usr/bin/env python3

# Does a bridge with bridge_fatal_sub_errors enabled
# disconnect on subscription errors? Does it remain connected otherwise?

from mosq_test_helper import *

def write_config(filename, port1, port2, fatal_sub_errors):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("connection bridge_sample\n")
        f.write("address 127.0.0.1:%d\n" % (port1))
        f.write("topic in_topic in\n")
        f.write("notifications false\n")
        f.write("restart_timeout 5\n")
        f.write("cleansession true\n")
        f.write("bridge_fatal_sub_errors %s\n" % str(fatal_sub_errors).lower())

def is_connected(sock):
    try:
        sock.recv(1) # if still connected, the recv will timeout
        return False
    except TimeoutError as e:
        return True

def do_test(fatal_sub_errors):
    (port1, port2) = mosq_test.get_port(2)
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port1, port2, fatal_sub_errors)

    rc = 1
    client_id = socket.gethostname()+".bridge_sample"
    connect_packet = mosq_test.gen_connect(client_id, proto_ver=132)
    connack_packet = mosq_test.gen_connack()

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "in_topic", 0)
    suback_packet = mosq_test.gen_suback(mid, 0x80)

    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssock.settimeout(40)
    ssock.bind(('', port1))
    ssock.listen(1)

    broker = None

    try:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

        (bridge, address) = ssock.accept()
        bridge.settimeout(5)

        mosq_test.expect_packet(bridge, "connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "subscribe", subscribe_packet)
        bridge.send(suback_packet)

        time.sleep(0.25) # give the broker some time to react

        # if (connected and not fatal) or (disconnected and fatal): success, else: failure
        rc = 0 if is_connected(bridge) != fatal_sub_errors else 1
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        try:
            bridge.close()
        except NameError:
            pass

        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            rc = 1
        (stdo, stde) = broker.communicate()
        ssock.close()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)

do_test(True)
do_test(False)

exit(0)
