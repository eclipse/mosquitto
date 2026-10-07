#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_TLS", "WITH_TLS_PSK"])

connect_packet = mqtt_packets.gen_connect("no-psk-test-client")
connack_packet = mqtt_packets.gen_connack(rc=0)

mid = 1
subscribe_packet = mqtt_packets.gen_subscribe(mid, "psk/test", 0)
suback_packet = mqtt_packets.gen_suback(mid, 0)

publish_packet = mqtt_packets.gen_publish(topic="psk/test", payload="message", qos=0)

(port1, port2) = mosq_test.get_port(2)

broker_config = BrokerConfig(
    listeners = [
        ListenerConfig(
            port=port1,
            psk_hint="hint",
        ),
        ListenerConfig(port=port2)
    ],
    allow_anonymous=True,
    psk_file=source_dir/'08-tls-psk-pub.psk',
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port2)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    env = mosq_test.env_add_ld_library_path()
    pub = subprocess.Popen([Path('c', mosq_test.get_build_type(), '08-tls-psk-pub.exe'), str(port1)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if mosq_test.wait_for_subprocess(pub):
        raise RuntimeError("pub not terminated")
    if pub.returncode != 0:
        raise ValueError(pub.returncode)
    mosq_test.expect_packet(sock, "publish", publish_packet)
    sock.close()
