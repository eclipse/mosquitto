#!/usr/bin/env python3

#

from mosq_test_helper import *

def do_test():
    rc = 1

    port = mosq_test.get_port()

    env = {
        'XDG_CONFIG_HOME':'/tmp/missing'
    }
    env = mosq_test.env_add_ld_library_path(env)
    cmd = [mosq_paths.mosquitto_sub,
            '-p', str(port),
            '-q', '0',
            '-t', 'retain-handling',
            '-V', '5',
            '-C', '1'
            ]

    sock = mosq_test.listen_sock(port)

    props = mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 1)
    connect_packet = mqtt_packets.gen_connect("", proto_ver=5, properties=props)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    subscribe_packet_always = mqtt_packets.gen_subscribe(mid=1, topic="retain-handling", qos=0x00, proto_ver=5)
    subscribe_packet_new = mqtt_packets.gen_subscribe(mid=1, topic="retain-handling", qos=0x10, proto_ver=5)
    subscribe_packet_never = mqtt_packets.gen_subscribe(mid=1, topic="retain-handling", qos=0x20, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid=1, qos=0)

    publish_packet = mqtt_packets.gen_publish("retain-handling", qos=0, payload="m", proto_ver=5)

    client_terminate_rc = 0

    try:
        for subscribe_packet, handling in [
                (subscribe_packet_always, 'always'),
                (subscribe_packet_new, 'new'),
                (subscribe_packet_never, 'never')]:

            client_cmd = cmd + ['--retain-handling', handling]
            client = subprocess.Popen(client_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)

            (conn, address) = sock.accept()
            conn.settimeout(5)

            mosq_test.expect_packet(conn, "connect", connect_packet)
            conn.send(connack_packet)

            mosq_test.expect_packet(conn, f"subscribe {handling}", subscribe_packet)
            conn.send(suback_packet)
            conn.send(publish_packet)

            if mosq_test.wait_for_subprocess(client):
                print("client not terminated")
                client_terminate_rc = 1
        sock.close()
    except mosq_test.TestError:
        pass
    except Exception as e:
        print(e)
    finally:
        sock.close()
        client.terminate()
        exit(client_terminate_rc)


do_test()
