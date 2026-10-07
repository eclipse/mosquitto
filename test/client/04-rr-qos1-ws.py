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
    payload = "message"

    ports = mosq_test.get_port(2)

    cmd = [mosq_paths.mosquitto_rr,
            '-p', str(ports[0]),
            '-q', '1',
            '-t', '04/rr/qos1/test/request',
            '-e', '04/rr/qos1/test/response',
            '-V', V,
            '-m', payload,
            '--ws'
            ]

    if proto_ver == 5:
        props = mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "04/rr/qos1/test/response")
    else:
        props = None
    publish_packet_req = mqtt_packets.gen_publish("04/rr/qos1/test/request", qos=1, mid=1, payload=payload, proto_ver=proto_ver, properties=props)
    payload = "the response"
    publish_packet_resp = mqtt_packets.gen_publish("04/rr/qos1/test/response", qos=1, mid=2, payload=payload, proto_ver=proto_ver)
    puback_packet_req = mqtt_packets.gen_puback(1, proto_ver=proto_ver)
    puback_packet_resp = mqtt_packets.gen_puback(2, proto_ver=proto_ver)

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
        sock = mosq_test.sub_helper(port=ports[1], topic="04/rr/qos1/test/request", qos=1, proto_ver=proto_ver)

        rr = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

        mosq_test.expect_packet(sock, "publish", publish_packet_req)
        sock.send(puback_packet_req)

        sock.send(publish_packet_resp)
        mosq_test.expect_packet(sock, "puback", puback_packet_resp)

        if mosq_test.wait_for_subprocess(rr):
            raise RuntimeError("rr not terminated")
        sock.close()
        (stdo, stde) = rr.communicate()
        if stdo.decode('utf-8') != payload + '\n':
            raise ValueError(stdo.decode('utf-8'))


do_test(proto_ver=3)
do_test(proto_ver=4)
do_test(proto_ver=5)
