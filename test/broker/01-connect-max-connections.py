#!/usr/bin/env python3

# Test whether max_connections works with repeated connections

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("max_connections 10\n")

def test_iteration(port, connect_packets_ok, connack_packets_ok, connect_packet_bad, connack_packet_bad):
    socks = []

    # Open all allowed connections, a limit of 10
    for i in range(0, 10):
        socks.append(mosq_test.do_client_connect(connect_packets_ok[i], connack_packets_ok[i], port=port))

    # Try to open an 11th connection
    try:
        sock_bad = mosq_test.do_client_connect(connect_packet_bad, connack_packet_bad, port=port)
    except (ConnectionResetError, BrokenPipeError):
        # Expected behaviour
        pass
    except OSError as e:
        if e.errno == errno.ENOTCONN:
            pass
        else:
            raise e

    # Close all allowed connections
    for i in range(0, 10):
        socks[i].close()


def do_test():
    rc = 1

    connect_packets_ok = []
    connack_packets_ok = []
    for i in range(0, 10):
        connect_packets_ok.append(mosq_test.gen_connect("max-conn-%d"%i, proto_ver=5))
        connack_packets_ok.append(mosq_test.gen_connack(rc=0, proto_ver=5))

    connect_packet_bad = mosq_test.gen_connect("max-conn-bad", proto_ver=5)
    connack_packet_bad = b""

    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        test_iteration(port, connect_packets_ok, connack_packets_ok, connect_packet_bad, connack_packet_bad)

        ## Now repeat - check it works as before

        if os.environ.get('MOSQ_USE_VALGRIND') is not None:
            time.sleep(0.5)

        test_iteration(port, connect_packets_ok, connack_packets_ok, connect_packet_bad, connack_packet_bad)

        rc = 0
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
    return rc

sys.exit(do_test())
