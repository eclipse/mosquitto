#!/usr/bin/env python3

#

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker
import platform

mosq_test.require_features(["WITH_BROKER", "WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"])
if platform.system() == 'Windows':
    # Long command line args not supported
    exit(0)

def do_test(proto_ver):
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

    payload = "abcdefghijklmnopqrstuvwxyz0123456789"*1821

    ports = mosq_test.get_port(2)

    cmd = [mosq_paths.mosquitto_pub,
            '-p', str(ports[0]),
            '-q', '1',
            '-t', '03/pub/qos1/test',
            '-m', payload,
            '-V', V,
            '--ws'
            ]

    mid = 1
    publish_packet = mqtt_packets.gen_publish("03/pub/qos1/test", qos=1, mid=mid, payload=payload, proto_ver=proto_ver)
    if proto_ver == 5:
        puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver, reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS)
    else:
        puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)

    broker_config = BrokerConfig(
        listeners = [
            ListenerConfig(
                port=ports[0],
                protocol="websockets",
            ),
            ListenerConfig(port=ports[1]),
        ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=ports[1], use_conf=True)
        sock = mosq_test.sub_helper(port=ports[1], topic="#", qos=1, proto_ver=proto_ver)

        pub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if mosq_test.wait_for_subprocess(pub):
            raise RuntimeError("pub not terminated")
        mosq_test.expect_packet(sock, "publish", publish_packet)
        sock.close()


do_test(proto_ver=3)
do_test(proto_ver=4)
do_test(proto_ver=5)
