#!/usr/bin/env python3

# Test whether a plugin can subscribe to the tick event

from mosq_test_helper import *

def write_config(filename, port, per_listener_settings="false"):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener_settings))
        f.write("listener %d\n" % (port))
        f.write("plugin c/auth_plugin_v5_handle_tick.so\n")
        f.write("allow_anonymous true\n")

def do_test(per_listener_settings):
    proto_ver = 5
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, per_listener_settings)

    rc = 1
    keepalive = 10
    connect_packet = mosq_test.gen_connect("plugin-tick-test", keepalive=keepalive, username="readwrite", clean_session=False, proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    tick_packet = mosq_test.gen_publish("topic/tick", qos=0, payload="test-message", proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=10, port=port)

        mosq_test.expect_packet(sock, "tick message", tick_packet)
        mosq_test.expect_packet(sock, "tick message", tick_packet)
        mosq_test.expect_packet(sock, "tick message", tick_packet)

        mosq_test.do_ping(sock)

        rc = 0
        sock.close()
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        broker.terminate()
        broker.wait()
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)

do_test("false")
do_test("true")
