#!/usr/bin/env python3

# Bug specific test - if a QoS2 publish is denied, then we publish again with
# the same mid to a topic that is allowed, does it work properly?

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

def do_test():
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    rc = 1
    connect_packet = mqtt_packets.gen_connect("connect-uname-pwd-test", username="test-username", password="cnwTICONIURW", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    mid = 1
    props = mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "custom-name", "custom-value")
    publish_allowed_packet = mqtt_packets.gen_publish("bad-topic", qos=1, mid=mid, payload="message", properties=props, proto_ver=5)
    puback_allowed_packet = mqtt_packets.gen_puback(mid, reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS, proto_ver=5)

    mid = 2
    publish_denied_packet = mqtt_packets.gen_publish("bad-topic", qos=1, mid=mid, payload="message", proto_ver=5)
    puback_denied_packet = mqtt_packets.gen_puback(mid, reason_code=mqtt5_rc.NOT_AUTHORIZED, proto_ver=5)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        plugins = [
            PluginConfig(path=mosq_paths.test_plugin('auth_plugin_v5'))
        ],
        allow_anonymous=False,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)

        mosq_test.do_send_receive(sock, publish_allowed_packet, puback_allowed_packet, "puback allowed")
        mosq_test.do_send_receive(sock, publish_denied_packet, puback_denied_packet, "puback denied")
        sock.close()
