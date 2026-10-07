#!/usr/bin/env python3

# Test $CONTROL/broker/v1 listListeners

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker
import json
import shutil

mosq_test.require_features(["WITH_CONTROL"])

def command_check(sock, command_payload, expected_response):
    command_packet = mqtt_packets.gen_publish(topic="$CONTROL/missing-endpoint/v1", qos=0, payload=json.dumps(command_payload))
    sock.send(command_packet)
    response = json.loads(mosq_test.read_publish(sock))
    if response != expected_response:
        print(expected_response)
        print(response)
        raise ValueError(response)


connect_packet = mqtt_packets.gen_connect("17-missing-endpoint")
connack_packet = mqtt_packets.gen_connack(rc=0)

mid = 2
subscribe_packet = mqtt_packets.gen_subscribe(mid, "$CONTROL/missing-endpoint/#", 0)
suback_packet = mqtt_packets.gen_suback(mid, 0)

port = mosq_test.get_port()
broker_config = BrokerConfig(
    allow_anonymous=True,
    enable_control_api=True,
)
broker = MosquittoBroker(port=port, config=broker_config)
with broker:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    cmd = {"commands":[{"command": "listListeners", "correlationData": "m3CtYVnySLCOwnHzITSeowvgla0InV4G"}]}
    response = {"error": "endpoint not available"}
    command_check(sock, cmd, response)
    mosq_test.do_ping(sock)
    sock.close()
