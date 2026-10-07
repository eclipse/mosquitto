#!/usr/bin/env python3

# Does a bridge resend a QoS=1 message correctly after a disconnect?

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, MQTTBridgeConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])

def do_test(proto_ver):
    if proto_ver == 4:
        bridge_protocol = "mqttv311"
        proto_ver_connect = 128+4
    else:
        bridge_protocol = "mqttv50"
        proto_ver_connect = 5

    client_id = socket.gethostname()+".bridge_sample"
    properties = mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS_MAXIMUM, 10)
    properties += mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 20)
    connect_packet = mqtt_packets.gen_connect(client_id, clean_session=False, proto_ver=proto_ver_connect, properties=properties)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    if proto_ver == 5:
        opts = mqtt5_opts.MQTT_SUB_OPT_NO_LOCAL | mqtt5_opts.MQTT_SUB_OPT_RETAIN_AS_PUBLISHED
    else:
        opts = 0

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "bridge/#", 2 | opts, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 2, proto_ver=proto_ver)

    mid = 2
    subscribe2_packet = mqtt_packets.gen_subscribe(mid, "bridge/#", 2 | opts, proto_ver=proto_ver)
    suback2_packet = mqtt_packets.gen_suback(mid, 2, proto_ver=proto_ver)

    mid = 3
    subscribe3_packet = mqtt_packets.gen_subscribe(mid, "bridge/#", 2 | opts, proto_ver=proto_ver)
    suback3_packet = mqtt_packets.gen_suback(mid, 2, proto_ver=proto_ver)

    mid = 5
    publish_packet = mqtt_packets.gen_publish("bridge/disconnect/test", qos=2, mid=mid, payload="disconnect-message", proto_ver=proto_ver)
    publish_dup_packet = mqtt_packets.gen_publish("bridge/disconnect/test", qos=2, mid=mid, payload="disconnect-message", dup=True, proto_ver=proto_ver)
    pubrec_packet = mqtt_packets.gen_pubrec(mid, proto_ver=proto_ver)
    pubrel_packet = mqtt_packets.gen_pubrel(mid, proto_ver=proto_ver)
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid, proto_ver=proto_ver)

    (port1, port2) = mosq_test.get_port(2)

    ssock = mosq_test.listen_sock(port1)

    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port2) ],
        bridges = [MQTTBridgeConfig(
            connection="bridge_sample",
            address=f"localhost:{port1}",
            topics=["bridge/# both 2"],
            notifications=False,
            restart_timeout=1,
            bridge_protocol_version=bridge_protocol,
        )],
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)
        (bridge, address) = ssock.accept()
        bridge.settimeout(20)

        mosq_test.expect_packet(bridge, "connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "subscribe", subscribe_packet)
        bridge.send(suback_packet)

        bridge.send(publish_packet)
        bridge.close()

        (bridge, address) = ssock.accept()
        bridge.settimeout(20)

        mosq_test.expect_packet(bridge, "connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "2nd subscribe", subscribe2_packet)
        bridge.send(suback2_packet)
        bridge.send(publish_dup_packet)

        mosq_test.expect_packet(bridge, "pubrec", pubrec_packet)
        bridge.send(pubrel_packet)
        bridge.close()

        (bridge, address) = ssock.accept()
        bridge.settimeout(20)

        mosq_test.expect_packet(bridge, "connect", connect_packet)
        bridge.send(connack_packet)

        mosq_test.expect_packet(bridge, "3rd subscribe", subscribe3_packet)
        bridge.send(suback3_packet)

        bridge.send(publish_dup_packet)

        mosq_test.expect_packet(bridge, "2nd pubrec", pubrec_packet)
        bridge.send(pubrel_packet)

        mosq_test.expect_packet(bridge, "pubcomp", pubcomp_packet)
        bridge.close()


do_test(proto_ver=4)
do_test(proto_ver=5)
