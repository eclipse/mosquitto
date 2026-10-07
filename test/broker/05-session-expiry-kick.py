#!/usr/bin/env python3

# MQTT v5. Test whether session expiry interval works correctly.

from mosq_test_helper import *
from broker_config import BrokerConfig, ListenerConfig

def do_test():
    port = mosq_test.get_port()

    # Test the case of connect with session-expiry>0, kick, expiry for a crash
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.SESSION_EXPIRY_INTERVAL, 1)
    connect_packet = mqtt_packets.gen_connect("05-session-expiry", clean_session=False, proto_ver=5, properties=props)
    connack_packet = mqtt_packets.gen_connack(flags=0, rc=0, proto_ver=5)

    config = BrokerConfig(
        allow_anonymous=True,
        log_type="all",
    )
    broker = MosquittoBroker(port=port, config=config)
    with broker:
        sock = mosq_test.client_connect_only(port=port)
        sock.send(connect_packet)
        # Immediately disconnect, this should now be queued to expire, but the plugin should kick it first
        sock.close()

        time.sleep(2)

        # This should succeed if the broker is still online
        # The "session present" flag must *not* be set
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port, connack_error="connack 1")
        sock.close()

do_test()
