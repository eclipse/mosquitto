#!/usr/bin/env python3

# Test whether global_max_clients works

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("global_max_clients 10\n")

def do_test():
    rc = 1

    connect_packets_ok = []
    connack_packets_ok = []
    connect_props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 60)
    for i in range(0, 10):
        connect_packets_ok.append(mosq_test.gen_connect("max-conn-%d"%i, proto_ver=5, properties=connect_props))
        connack_packets_ok.append(mosq_test.gen_connack(rc=0, proto_ver=5))

    connect_packet_bad = mosq_test.gen_connect("max-conn-bad", proto_ver=5)
    connack_packet_bad = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_SERVER_BUSY, proto_ver=5, property_helper=False)

    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    socks = []
    try:
        # Open all allowed connections, a limit of 10
        for i in range(0, 10):
            socks.append(mosq_test.do_client_connect(connect_packets_ok[i], connack_packets_ok[i], port=port))

        # Try to open an 11th connection
        try:
            sock_bad = mosq_test.do_client_connect(connect_packet_bad, connack_packet_bad, port=port)
        except ConnectionResetError:
            # Expected behaviour
            pass

        # Close all allowed connections
        for i in range(0, 10):
            socks[i].close()

        ## Session expiry means those clients sessions are still active

        # Try to open an 11th connection
        try:
            sock_bad = mosq_test.do_client_connect(connect_packet_bad, connack_packet_bad, port=port)
        except ConnectionResetError:
            # Expected behaviour
            pass

        rc = 0
    except mosq_test.TestError:
        pass
    except Exception as err:
        print(err)
    finally:
        os.remove(conf_file)
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)

do_test()
exit(0)
