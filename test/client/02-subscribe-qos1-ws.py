#!/usr/bin/env python3

#

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_BROKER", "WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"])

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

    ports = mosq_test.get_port(2)

    cmd = [mosq_paths.mosquitto_sub,
            '-p', str(ports[0]),
            '-q', '1',
            '-t', '02/sub/qos1/test',
            '-V', V,
            '-C', '1',
            '--ws'
            ]

    payload = "message"
    publish_packet_s = mqtt_packets.gen_publish("02/sub/qos1/test", qos=1, mid=1, payload=payload, proto_ver=proto_ver)
    puback_packet_s = mqtt_packets.gen_puback(1, proto_ver=proto_ver)

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

        sock = mosq_test.pub_helper(port=ports[1], proto_ver=proto_ver)

        sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        time.sleep(0.1)
        sock.send(publish_packet_s)
        mosq_test.expect_packet(sock, "puback", puback_packet_s)
        if mosq_test.wait_for_subprocess(sub):
            raise RuntimeError("sub not terminated")
        sock.close()
        (stdo, stde) = sub.communicate()
        if stdo.decode('utf-8') != payload + '\n':
            raise ValueError(stdo.decode('utf-8'))


do_test(proto_ver=3)
do_test(proto_ver=4)
do_test(proto_ver=5)
