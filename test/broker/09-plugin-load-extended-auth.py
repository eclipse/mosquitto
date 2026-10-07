#!/usr/bin/env python3

# Test whether a plugin can subscribe to the tick event

from mosq_test_helper import *

def write_config(filename, ports, per_listener_settings):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener_settings))
        f.write(f"plugin_load auth {mosq_paths.test_plugin('plugin_load_extended_auth')}\n")

        f.write("listener %d\n" % (ports[0]))
        f.write("plugin_use auth\n")

        f.write("listener %d\n" % (ports[1]))

def client_check_start_denied(start_data, rc, port):
    props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "test")
    props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, start_data)
    connect_packet = mqtt_packets.gen_connect(client_id="id", proto_ver=5, properties=props)
    connack_packet = mqtt_packets.gen_connack(rc=rc, proto_ver=5)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        sock.close()
    except BrokenPipeError:
        if rc == mqtt5_rc.NOT_AUTHORIZED or rc == mqtt5_rc.BAD_AUTHENTICATION_METHOD:
            return
        else:
            raise
        return


def client_check_start_allowed(start_data, cont_data, rc, port):
    props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "test")
    props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, start_data)
    connect_packet = mqtt_packets.gen_connect(client_id="id", proto_ver=5, properties=props)

    props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "test")
    props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "start-ok")
    auth_packet_recv = mqtt_packets.gen_auth(reason_code=mqtt5_rc.CONTINUE_AUTHENTICATION, properties=props)

    props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "test")
    props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, cont_data)
    auth_packet_send = mqtt_packets.gen_auth(reason_code=mqtt5_rc.CONTINUE_AUTHENTICATION, properties=props)

    props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "test")
    connack_packet = mqtt_packets.gen_connack(rc=rc, proto_ver=5, properties=props)

    sock = mosq_test.do_client_connect(connect_packet, auth_packet_recv, port=port)
    try:
        mosq_test.do_send_receive(sock, auth_packet_send, connack_packet, f"connack {cont_data}")
        sock.close()
    except BrokenPipeError:
        if rc == mqtt5_rc.NOT_AUTHORIZED:
            return
        else:
            raise


def do_test(per_listener_settings):
    proto_ver = 5
    ports = mosq_test.get_port(2)
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, ports, per_listener_settings)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=ports[0])

    rc = 1
    try:
        # Plugin loaded
        client_check_start_denied("denied-start", mqtt5_rc.NOT_AUTHORIZED, ports[0]) # Should fail
        client_check_start_allowed("allowed-start", "denied-continue", mqtt5_rc.NOT_AUTHORIZED, ports[0]) # Should fail
        client_check_start_allowed("allowed-start", "allowed-continue", mqtt5_rc.SUCCESS, ports[0]) # Should succeed
        # No plugin
        client_check_start_denied("denied-topic", mqtt5_rc.BAD_AUTHENTICATION_METHOD, ports[1]) # Should fail
        client_check_start_denied("allowed-topic", mqtt5_rc.BAD_AUTHENTICATION_METHOD, ports[1]) # Should fail

        rc = 0
    except Exception as err:
        print(err)
    finally:
        os.remove(conf_file)
        mosq_test.terminate_broker(broker)
        broker.wait()
        if rc:
            print(f"per_listener_settings:{per_listener_settings}")
            print(mosq_test.broker_log(broker))
            exit(rc)

do_test("false")
do_test("true")
