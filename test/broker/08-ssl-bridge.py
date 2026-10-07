#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, MQTTBridgeConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["INC_BRIDGE_SUPPORT", "WITH_TLS"])

source_dir = Path(__file__).resolve().parent
ssl_dir = source_dir.parent / "ssl"

def pub_helper(port):
    connect_packet = mqtt_packets.gen_connect("test-helper")
    connack_packet = mqtt_packets.gen_connack(rc=0)
    publish_packet = mqtt_packets.gen_publish("bridge/ssl/test", qos=0, payload="message")
    disconnect_packet = mqtt_packets.gen_disconnect()
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port, connack_error="helper connack")
    sock.send(publish_packet)
    sock.send(disconnect_packet)
    sock.close()

def do_test(address):
    (port1, port2) = mosq_test.get_port(2)

    client_id = socket.gethostname()+".bridge_test"
    connect_packet = mqtt_packets.gen_connect(client_id, clean_session=False, proto_ver=128+4)
    connack_packet = mqtt_packets.gen_connack(rc=0)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "bridge/#", 0)
    suback_packet = mqtt_packets.gen_suback(mid, 0)

    publish_packet = mqtt_packets.gen_publish("bridge/ssl/test", qos=0, payload="message")

    ssock = mosq_test.listen_sock(port1, f"{ssl_dir}/all-ca.crt", f"{ssl_dir}/server-san.crt", f"{ssl_dir}/server-san.key")

    broker_config = BrokerConfig(
        listeners = [ListenerConfig(port=port2)],
        bridges = [MQTTBridgeConfig(
            connection="bridge_test",
            address=f"{address}:{port1}",
            topics=["bridge/# both 0"],
            notifications=False,
            restart_timeout=2,
            bridge_cafile=ssl_dir/'all-ca.crt',
            bridge_insecure=True,
        )],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        (bridge, address) = ssock.accept()
        bridge.settimeout(20)

        mosq_test.expect_packet(bridge, "connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "subscribe", subscribe_packet)
        bridge.send(suback_packet)

        pub_helper(port2)

        mosq_test.expect_packet(bridge, "publish", publish_packet)

        bridge.close()
        ssock.close()

do_test("127.0.0.1")
do_test(mosq_test.get_non_loopback_ip()) # tests non-matching certificate hostname with bridge_insecure
