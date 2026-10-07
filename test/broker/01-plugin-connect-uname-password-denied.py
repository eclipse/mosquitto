#!/usr/bin/env python3

# Test whether a connection is denied if it provides a correct username but
# incorrect password.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_PLUGINS", "WITH_PLUGIN_PASSWORD_FILE", "WITH_TLS"])

def do_test(proto_ver):
    connect_packet = mqtt_packets.gen_connect("connect-uname-pwd-test", username="user", password="password9", proto_ver=proto_ver)
    if proto_ver == 5:
        connack_packet = mqtt_packets.gen_connack(rc=mqtt5_rc.NOT_AUTHORIZED, proto_ver=proto_ver, properties=None)
    else:
        connack_packet = mqtt_packets.gen_connack(rc=5, proto_ver=proto_ver)


    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        plugins = [
            PluginConfig(
                path=mosq_paths.plugin_password_file,
                options = {
                    "plugin_opt_password_file": Path(__file__).resolve().parent / os.path.basename(__file__).replace('.py', '.pwfile')
                }
            )
        ],
        allow_anonymous=False,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        sock.close()


do_test(proto_ver=4)
do_test(proto_ver=5)
