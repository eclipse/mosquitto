#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, MQTTBridgeConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])

connect_packet = mqtt_packets.gen_connect("no-psk-test-client")
connack_packet = mqtt_packets.gen_connack(rc=0)

mid = 1
subscribe_packet = mqtt_packets.gen_subscribe(mid, "psk/test", 0)
suback_packet = mqtt_packets.gen_suback(mid, 0)

publish_packet = mqtt_packets.gen_publish(topic="psk/test", payload="message", qos=0)

(port1, port2, port3) = mosq_test.get_port(3)
broker_config = BrokerConfig(
    listeners=[
        ListenerConfig(port=port1),
        ListenerConfig(
            port=port2,
            psk_hint="hint",
        ),
    ],
    psk_file=source_dir/'08-tls-psk-bridge.psk',
    allow_anonymous=True,
)
bridge_config = BrokerConfig(
    listeners=[ ListenerConfig(port=port3) ],
    bridges=[
        MQTTBridgeConfig(
            connection="bridge-psk",
            address=f"localhost:{port2}",
            topics=["psk/test out"],
            bridge_identity="psk-test",
            bridge_psk="deadbeef",
        )
    ],
    allow_anonymous=True,
)

broker = MosquittoBroker(config=broker_config)
bridge = MosquittoBroker(config=bridge_config)

pub = None
with broker, bridge:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=30, port=port1)

    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    env = mosq_test.env_add_ld_library_path()
    pub = subprocess.run([Path('c', mosq_test.get_build_type(), '08-tls-psk-bridge.exe'), str(port3)], env=env, capture_output=True, encoding='utf-8')
    if pub.returncode != 0:
        print("d")
        print(pub.returncode)
        raise ValueError

    mosq_test.expect_packet(sock, "publish", publish_packet)
    sock.close()
    if pub.returncode:
        raise RuntimeError(pub.returncode)
