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
            '-q', '0',
            '-t', '02/sub/filter-out/#',
            '-T', '02/sub/filter-out/filtered',
            '-V', V,
            '-C', '2'
            ]

    publish_packet1 = mqtt_packets.gen_publish("02/sub/filter-out/recv", qos=0, payload="recv", proto_ver=proto_ver)
    publish_packet2 = mqtt_packets.gen_publish("02/sub/filter-out/filtered", qos=0, payload="filtered", proto_ver=proto_ver)

    sock = mosq_test.pub_helper(port=port, proto_ver=proto_ver)

    sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    time.sleep(0.1)
    sock.send(publish_packet1)
    sock.send(publish_packet2)
    sock.send(publish_packet1)
    sock.send(publish_packet2)
    sub_terminate_rc = 0
    if mosq_test.wait_for_subprocess(sub):
        print("sub not terminated")
        sub_terminate_rc = 1
    (stdo, stde) = sub.communicate()
    if stdo.decode('utf-8') == 'recv\nrecv\n':
        rc = sub_terminate_rc
    else:
        print(stdo.decode('utf-8'))
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
