#!/usr/bin/env python3

# Check whether an extended auth plugin can change the username of a client.

from mosq_test_helper import *

def write_config(filename, acl_file, port, per_listener):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener))
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("acl_file %s\n" % (acl_file))
        f.write("auth_plugin c/auth_plugin_extended_single.so\n")

def write_acl(filename):
    with open(filename, 'w') as f:
        f.write('user new_username\n')
        f.write('topic readwrite topic/one\n')

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
acl_file = os.path.basename(__file__).replace('.py', '.acl')

def do_test(per_listener):
    write_config(conf_file, acl_file, port, per_listener)
    write_acl(acl_file)
    rc = 1

    # Connect without a username - this means no access
    connect1_packet = mosq_test.gen_connect("client-params-test1", proto_ver=5)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "topic/one", 1, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 1, proto_ver=5)

    mid = 2
    publish1_packet = mosq_test.gen_publish("topic/one", qos=1, mid=mid, payload="message", proto_ver=5)
    puback1_packet = mosq_test.gen_puback(mid, proto_ver=5, reason_code=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED)

    # Connect without a username, but have the plugin change it
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "change")
    connect2_packet = mosq_test.gen_connect("client-params-test2", proto_ver=5, properties=props)
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "change")
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props)

    mid = 2
    publish2s_packet = mosq_test.gen_publish("topic/one", qos=1, mid=mid, payload="message", proto_ver=5)
    puback2s_packet = mosq_test.gen_puback(mid, proto_ver=5)

    mid = 1
    publish2r_packet = mosq_test.gen_publish("topic/one", qos=1, mid=mid, payload="message", proto_ver=5)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback1")
        mosq_test.do_send_receive(sock, publish1_packet, puback1_packet, "puback1")
        mosq_test.do_ping(sock)
        sock.close()

        sock = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback2")
        sock.send(publish2s_packet)
        mosq_test.receive_unordered(sock, puback2s_packet, publish2r_packet, "puback2/publish2")
        mosq_test.do_ping(sock)
        rc = 0

        sock.close()

    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        os.remove(acl_file)
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)


do_test("true")
do_test("false")
exit(0)
