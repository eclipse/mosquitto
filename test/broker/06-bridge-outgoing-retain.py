#!/usr/bin/env python3

# Does a bridge with bridge_outgoing_retain set to false not set the retain bit
# on outgoing messages?

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, MQTTBridgeConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])

def do_test(proto_ver, outgoing_retain):
    if proto_ver == 4:
        bridge_protocol = "mqttv311"
        proto_ver_connect = 128+4
    else:
        bridge_protocol = "mqttv50"
        proto_ver_connect = 5

    client_id = socket.gethostname()+".bridge_sample"
    connect_packet = mqtt_packets.gen_connect(client_id, clean_session=False, proto_ver=proto_ver_connect)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    if proto_ver == 5:
        opts = mqtt5_opts.MQTT_SUB_OPT_NO_LOCAL | mqtt5_opts.MQTT_SUB_OPT_RETAIN_AS_PUBLISHED
    else:
        opts = 0

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "bridge with space/#", 1 | opts, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=proto_ver)

    if outgoing_retain == True:
        publish_packet = mqtt_packets.gen_publish("bridge with space/retain/test", qos=0, retain=True, payload="message", proto_ver=proto_ver)
    else:
        publish_packet = mqtt_packets.gen_publish("bridge with space/retain/test", qos=0, retain=False, payload="message", proto_ver=proto_ver)


    helper_connect_packet = mqtt_packets.gen_connect("helper", clean_session=True, proto_ver=proto_ver)
    helper_connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
    helper_publish_packet = mqtt_packets.gen_publish("bridge with space/retain/test", qos=0, retain=True, payload="message", proto_ver=proto_ver)

    (port1, port2) = mosq_test.get_port(2)

    ssock = mosq_test.listen_sock(port1)

    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port2) ],
        bridges = [
            MQTTBridgeConfig(
                connection="bridge_sample",
                address=f"localhost:{port1}",
                topics=["\"bridge with space/#\" both 1"],
                notifications=False,
                restart_timeout=5,
                bridge_protocol_version=bridge_protocol,
                bridge_outgoing_retain=outgoing_retain,
                bridge_max_topic_alias=0,
            ),
        ],
        allow_anonymous=True,
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

        # Broker is now connected to us on port1.
        # Connect our client to the broker on port2 and send a publish
        # message, which we will then receive by way of the bridge
        helper = mosq_test.do_client_connect(helper_connect_packet, helper_connack_packet, port=port2)
        helper.send(helper_publish_packet)
        helper.close()

        mosq_test.expect_packet(bridge, "publish", publish_packet)
        bridge.close()

do_test(proto_ver=4, outgoing_retain=True)
do_test(proto_ver=4, outgoing_retain=False)
do_test(proto_ver=5, outgoing_retain=True)
do_test(proto_ver=5, outgoing_retain=False)
