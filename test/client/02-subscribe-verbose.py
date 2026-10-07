#!/usr/bin/env python3

#

from mosq_test_helper import *

mosq_test.require_features(["WITH_BROKER"])

def do_test(port, proto_ver):
    rc = 1

    if proto_ver == 5:
        V = 'mqttv5'
    elif proto_ver == 4:
        V = 'mqttv311'
    else:
        V = 'mqttv31'

    env = {
        'XDG_CONFIG_HOME':'/tmp/missing'
    }
    env = mosq_test.env_add_ld_library_path(env)
    cmd = [mosq_paths.mosquitto_sub,
            '-p', str(port),
            '-q', '1',
            '-t', '02/sub/verbose/test',
            '-V', V,
            '-C', '1',
            '-v'
            ]

    topic = "02/sub/verbose/test"
    payload = "message"
    publish_packet_s = mqtt_packets.gen_publish(topic, qos=1, mid=1, payload=payload, proto_ver=proto_ver)
    publish_packet_r = mqtt_packets.gen_publish(topic, qos=1, mid=2, payload=payload, proto_ver=proto_ver)
    puback_packet_s = mqtt_packets.gen_puback(1, proto_ver=proto_ver)
    puback_packet_r = mqtt_packets.gen_puback(2, proto_ver=proto_ver)

    sock = mosq_test.pub_helper(port=port, proto_ver=proto_ver)

    sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    time.sleep(0.1)
    sock.send(publish_packet_s)
    mosq_test.expect_packet(sock, "puback", puback_packet_s)
    sub_terminate_rc = 0
    if mosq_test.wait_for_subprocess(sub):
        print("sub not terminated")
        sub_terminate_rc = 1
    (stdo, stde) = sub.communicate()
    expected_output = topic + ' ' + payload + '\n'
    if stdo.decode('utf-8') == expected_output:
        rc = sub_terminate_rc
    else:
        print("expected: %s" % expected_output)
        print("actual:   %s"  % stdo.decode('utf-8'))
    sock.close()
    if rc:
        raise ValueError(rc)


if __name__ == '__main__':
    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        do_test(port, proto_ver=3)
        do_test(port, proto_ver=4)
        do_test(port, proto_ver=5)
