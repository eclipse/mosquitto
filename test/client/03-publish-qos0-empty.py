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
    cmd = [mosq_paths.mosquitto_pub,
            '-p', str(port),
            '-q', '0',
            '-t', '03/pub/qos0/test',
            '-n',
            '-V', V
            ]

    mid = 1
    publish_packet = mqtt_packets.gen_publish("03/pub/qos0/test", qos=0, mid=mid, payload="", proto_ver=proto_ver)
    if proto_ver == 5:
        puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver, reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS)
    else:
        puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)

    sock = mosq_test.sub_helper(port=port, topic="#", qos=0, proto_ver=proto_ver)

    pub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    pub_terminate_rc = 0
    if mosq_test.wait_for_subprocess(pub):
        print("pub not terminated")
        pub_terminate_rc = 1
    (stdo, stde) = pub.communicate()

    mosq_test.expect_packet(sock, "publish", publish_packet)
    rc = pub_terminate_rc
    sock.close()

    if rc:
        print(stde.decode('utf-8'))
        print("proto_ver=%d" % (proto_ver))


if __name__ == '__main__':
    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        do_test(port, proto_ver=3)
        do_test(port, proto_ver=4)
        do_test(port, proto_ver=5)
