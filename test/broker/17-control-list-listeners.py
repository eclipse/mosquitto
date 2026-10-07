#!/usr/bin/env python3

# Test $CONTROL/broker/v1 listListeners

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
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

ports = mosq_test.get_port(4)
broker_config = BrokerConfig(
    listeners = [
        ListenerConfig(
            port=ports[0],
            protocol="mqtt"
        )
    ],
    allow_anonymous=True,
    enable_control_api=True
)
if mosq_test.check_features(["WITH_WEBSOCKETS"]):
    broker_config.listeners.append(ListenerConfig(
        port=ports[1],
        protocol="websockets"
    ))
if mosq_test.check_features(["WITH_TLS"]):
    broker_config.listeners.append(ListenerConfig(
        port=ports[2],
        protocol="mqtt",
        certfile=ssl_dir/"server.crt",
        keyfile=ssl_dir/"server.key",
    ))
if mosq_test.check_features(["WITH_TLS", "WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"]):
    broker_config.listeners.append(ListenerConfig(
        port=ports[3],
        protocol="websockets",
        certfile=ssl_dir/"server.crt",
        keyfile=ssl_dir/"server.key",
    ))
if mosq_test.check_features(["WITH_UNIX_SOCKETS"]):
    broker_config.listeners.append(ListenerConfig(
        port=0,
        address="17-list-listeners-mqtt.sock",
    ))
if mosq_test.check_features(["WITH_UNIX_SOCKETS", "WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"]):
    broker_config.listeners.append(ListenerConfig(
        port=0,
        address="17-list-listeners-websockets.sock",
        protocol="websockets",
    ))

cmd_success = {"commands":[{"command": "listListeners", "correlationData": "m3CtYVnySLCOwnHzITSeowvgla0InV4G"}]}

listeners = [{
    'port': ports[0],
    'protocol': 'mqtt',
    'tls': False
}]

if mosq_test.check_features(["WITH_WEBSOCKETS"]):
    listeners.append({
        'port': ports[1],
        'protocol': 'mqtt+websockets',
        'tls': False
    })


if mosq_test.check_features(["WITH_TLS"]):
    listeners.append({
        'port': ports[2],
        'protocol': 'mqtt',
        'tls': True

    })

if mosq_test.check_features(["WITH_TLS", "WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"]):
    listeners.append({
        'port': ports[3],
        'protocol': 'mqtt+websockets',
        'tls': True
    })

if mosq_test.check_features(["WITH_UNIX_SOCKETS"]):
    listeners.append({
        'port': 0,
        'protocol': 'mqtt',
        'socket-path': '17-list-listeners-mqtt.sock',
        'tls': False
    })

if mosq_test.check_features(["WITH_UNIX_SOCKETS", "WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"]):
    listeners.append({
        'port': 0,
        'protocol': 'mqtt+websockets',
        'socket-path': '17-list-listeners-websockets.sock',
        'tls': False
    })

response_success = {'responses': [{'command': 'listListeners', "correlationData": "m3CtYVnySLCOwnHzITSeowvgla0InV4G", 'data':{
    'listeners':listeners
    }
}]}

rc = 1
connect_packet = mqtt_packets.gen_connect("17-list-listeners")
connack_packet = mqtt_packets.gen_connack(rc=0)

mid = 2
subscribe_packet = mqtt_packets.gen_subscribe(mid, "$CONTROL/broker/#", 0)
suback_packet = mqtt_packets.gen_suback(mid, 0)

broker = MosquittoBroker(config=broker_config)
for f in ["17-list-listeners-mqtt.sock", "17-list-listeners-websockets.sock"]:
    broker.add_extra_file(f)
with broker:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=ports[0])
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
