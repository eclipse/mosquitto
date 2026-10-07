#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_PLUGINS", "WITH_PLUGIN_ACL_FILE"])

def broker_config_default(port):
    return BrokerConfig(
        listeners=[ListenerConfig(port=port)],
        acl_file=f"{port}.acl",
        allow_anonymous=True
    )

def broker_config_plugin(port):
    return BrokerConfig(
        listeners=[ListenerConfig(port=port)],
        plugins=[PluginConfig(
            path=mosq_paths.plugin_acl_file,
            options={
                "plugin_opt_acl_file": f"{port}.acl"
            }
        )],
        acl_file=f"{port}.acl",
        allow_anonymous=True,
    )


def do_test(broker_config_func):
    connect_packet = mqtt_packets.gen_connect("acl-change-test")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    port = mosq_test.get_port()
    with open(f"{port}.acl", "wt") as f:
        f.write("topic readwrite a/#")

    broker_config = broker_config_func(port)
    broker = MosquittoBroker(config=broker_config, expect_fail=True)
    broker.add_extra_file(f"{port}.acl")
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        sock.close()

        with open(f"{port}.acl", "wt") as f:
            f.write("topic readwrite a#")

        broker.reload()
        # Broker should terminate
        if mosq_test.wait_for_subprocess(broker.process) == 0 and broker.process.returncode == 3:
            pass
        else:
            raise RuntimeError("broker not terminated")

do_test(broker_config_default)
do_test(broker_config_plugin)
