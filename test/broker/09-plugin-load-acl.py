#!/usr/bin/env python3

# Test whether a plugin can subscribe to the tick event

from mosq_test_helper import *

def write_config(filename, ports, per_listener_settings):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener_settings))
        f.write(f"plugin_load acl {mosq_paths.test_plugin('plugin_load_acl')}\n")

        f.write("listener %d\n" % (ports[0]))
        f.write("listener_allow_anonymous true\n")
        f.write("plugin_use acl\n")

        f.write("listener %d\n" % (ports[1]))
        f.write("listener_allow_anonymous true\n")

def client_check(topic, rc, port):
    connect_packet = mqtt_packets.gen_connect(client_id="id", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)

    publish_packet = mqtt_packets.gen_publish(topic=topic, qos=1, mid=1, payload="message", proto_ver=5)
    puback_packet = mqtt_packets.gen_puback(mid=1, reason_code=rc, proto_ver=5)

    mosq_test.do_send_receive(sock, publish_packet, puback_packet, f"puback {topic}")

    sock.close()


def do_test(per_listener_settings):
    proto_ver = 5
    ports = mosq_test.get_port(2)
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, ports, per_listener_settings)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=ports[0])

    rc = 1
    try:
        # Plugin loaded
        client_check("denied-topic", mqtt5_rc.NOT_AUTHORIZED, ports[0]) # Should fail
        client_check("allowed-topic", mqtt5_rc.NO_MATCHING_SUBSCRIBERS, ports[0]) # Should succeed
        # No plugin
        client_check("denied-topic", mqtt5_rc.NO_MATCHING_SUBSCRIBERS, ports[1]) # Should succeed
        client_check("allowed-topic", mqtt5_rc.NO_MATCHING_SUBSCRIBERS, ports[1]) # Should succeed

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
