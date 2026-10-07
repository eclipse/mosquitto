#!/usr/bin/env python3

# Does a bridge resend a QoS=1 message correctly after a disconnect?

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, MQTTBridgeConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])

def do_test(proto_ver):
    keepalive = 600
    client_id = "mosquitto"
    properties = mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS_MAXIMUM, 10)
    properties += mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 20)
    connect_packet = mqtt_packets.gen_connect(client_id, keepalive=keepalive, clean_session=False, proto_ver=proto_ver, properties=properties)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    if proto_ver == 5:
        opts = mqtt5_opts.MQTT_SUB_OPT_NO_LOCAL | mqtt5_opts.MQTT_SUB_OPT_RETAIN_AS_PUBLISHED
    else:
        opts = 0

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "myhouse/room1/#", 2 | opts, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 2, proto_ver=proto_ver)

    mid = 2
    subscribe_packet2 = mqtt_packets.gen_subscribe(mid, "tst/ba", 2 | opts, proto_ver=proto_ver)
    suback_packet2= mqtt_packets.gen_suback(mid, 2, proto_ver=proto_ver)

    mid = 3
    subscribe_packet3 = mqtt_packets.gen_subscribe(mid, "#", 2 | opts, proto_ver=proto_ver)
    suback_packet3 = mqtt_packets.gen_suback(mid, 2, proto_ver=proto_ver)

    (port1, port2) = mosq_test.get_port(2)

    ssock = mosq_test.listen_sock(port1)

    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port2) ],
        bridges = [
            MQTTBridgeConfig(
                connection="bridge1",
                address=f"localhost:{port1}",
                topics=[
                    "room1/# both 2 sensor/ myhouse/",
                    "tst/ba both 2",
                    "# both 2",
                ],
                keepalive_interval=600,
                remote_clientid=client_id,
                bridge_protocol_version="mqttv50",
                notifications=False,
            ),
        ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        (bridge, address) = ssock.accept()
        bridge.settimeout(20)

        mosq_test.expect_packet(bridge, "connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "subscribe1", subscribe_packet)
        bridge.send(suback_packet)

        mosq_test.expect_packet(bridge, "subscribe2", subscribe_packet2)
        bridge.send(suback_packet2)

        mosq_test.expect_packet(bridge, "subscribe3", subscribe_packet3)
        bridge.send(suback_packet3)

        try:
            bridge.send(bytes.fromhex("320c00062b2b2b2b2b2b00040033"))
            #bridge.send(bytes.fromhex("320c00062b2b2b2b2b2b00040033"))
            #bridge.send(bytes.fromhex("320c00062b2b2b2b2b2b00040033"))
            bridge.send(bytes.fromhex("C000")) # PING
            d = bridge.recv(1)
            if len(d) > 0:
                raise ValueError(d)
        except (ConnectionResetError, BrokenPipeError):
            #expected behaviour
            pass
        bridge.close()


do_test(proto_ver=5)
