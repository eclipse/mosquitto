#!/usr/bin/env python3

# Test $CONTROL/broker/v1 listListeners

from mosq_test_helper import *

from broker_config import BrokerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker
import json
import shutil

mosq_test.require_features(["WITH_CONTROL"])

def command_check(sock, command_payload, expected_response):
    command_packet = mqtt_packets.gen_publish(topic="$CONTROL/broker/v1", qos=0, payload=json.dumps(command_payload))
    sock.send(command_packet)
    response = json.loads(mosq_test.read_publish(sock))
    if response != expected_response:
        print(expected_response)
        print(response)
        raise ValueError(response)

def invalid_command_check(sock, command_payload, cmd_name, error_msg):
    command_packet = mqtt_packets.gen_publish(topic="$CONTROL/broker/v1", qos=0, payload=command_payload)
    sock.send(command_packet)
    response = json.loads(mosq_test.read_publish(sock))
    expected_response = {'responses': [{'command': cmd_name, 'error': error_msg}]}
    if response != expected_response:
        print(expected_response)
        print(response)
        raise ValueError(response)



cmd_success = {"commands":[{"command": "listPlugins", "correlationData": "m3CtYVnySLCOwnHzITSeowvgla0InV4G"}]}

response_success = {'responses': [{'command': 'listPlugins', "correlationData": "m3CtYVnySLCOwnHzITSeowvgla0InV4G", 'data':{
    'plugins':[
        {
            'name': 'test-plugin',
            'control-endpoints': ['$CONTROL/test/v1']
        }
    ]}}]}

rc = 1
connect_packet = mqtt_packets.gen_connect("17-list-listeners")
connack_packet = mqtt_packets.gen_connack(rc=0)

mid = 2
subscribe_packet = mqtt_packets.gen_subscribe(mid, "$CONTROL/broker/#", 0)
suback_packet = mqtt_packets.gen_suback(mid, 0)

port = mosq_test.get_port()
broker_config = BrokerConfig(
    plugins=[PluginConfig(path=mosq_paths.test_plugin('auth_plugin_v5_control'))],
    allow_anonymous=True,
    enable_control_api=True,
)
broker = MosquittoBroker(port=port, config=broker_config)
for f in ["17-list-listeners-mqtt.sock", "17-list-listeners-websockets.sock"]:
    broker.add_extra_file(f)
with broker:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    invalid_command_check(sock, "not valid json", "Unknown command", "Payload not valid JSON")
    invalid_command_check(sock, "{}", "Unknown command", "Invalid/missing commands")

    cmd = {"commands":["command"]}
    invalid_command_check(sock, json.dumps(cmd), "Unknown command", "Command not an object")

    cmd = {"commands":[{}]}
    invalid_command_check(sock, json.dumps(cmd), "Unknown command", "Missing command")

    cmd = {"commands":[{"command": "unknown command"}]}
    invalid_command_check(sock, json.dumps(cmd), "unknown command", "Unknown command")

    cmd = {"commands":[{"command": "listListeners", "correlationData": True}]}
    invalid_command_check(sock, json.dumps(cmd), "listListeners", "Invalid correlationData data type.")

    command_check(sock, cmd_success, response_success)
    mosq_test.do_ping(sock)
    sock.close()
