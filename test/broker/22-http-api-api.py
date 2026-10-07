#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker
import http.client
import json
import re

mosq_test.require_features(["WITH_HTTP_API"])

def check_sys_tree(http_conn):
    http_conn.request("GET", "/api/v1/systree")
    response = http_conn.getresponse()
    if response.status != 200:
        raise ValueError(f"/api/v1/systree {response.status}")
    payload = json.loads(response.read().decode('utf-8'))

    topics = [
        '$SYS/broker/clients/connected',
        '$SYS/broker/clients/disconnected',
        '$SYS/broker/clients/maximum',
        '$SYS/broker/connections/socket/count',
        '$SYS/broker/messages/stored',
        '$SYS/broker/retained messages/count',
        '$SYS/broker/store/messages/bytes',
        '$SYS/broker/uptime'
    ]

    if mosq_test.check_features(["INC_MEMTRACK"]):
        topics.extend([
            '$SYS/broker/heap/current',
            '$SYS/broker/heap/maximum',
        ])

    for topic in topics:
        # Protect against values being slightly different by
        # setting to a known value
        # This read will fail if the key doesn't already exist
        if payload[topic] >= 0:
            payload[topic] = -1


    expected_payload = {
        '$SYS/broker/clients/total': 0,
        '$SYS/broker/clients/maximum': -1,
        '$SYS/broker/clients/disconnected': -1,
        '$SYS/broker/clients/connected': -1,
        '$SYS/broker/clients/expired': 0,
        '$SYS/broker/messages/stored': -1,
        '$SYS/broker/store/messages/bytes': -1,
        '$SYS/broker/subscriptions/count': 0,
        '$SYS/broker/shared_subscriptions/count': 0,
        '$SYS/broker/retained messages/count': -1,
        '$SYS/broker/messages/received': 0,
        '$SYS/broker/messages/sent': 0,
        '$SYS/broker/bytes/received': 0,
        '$SYS/broker/bytes/sent': 0,
        '$SYS/broker/publish/bytes/received': 0,
        '$SYS/broker/publish/bytes/sent': 0,
        '$SYS/broker/packet/out/count': 0,
        '$SYS/broker/packet/out/bytes': 0,
        '$SYS/broker/connections/socket/count': -1,
        '$SYS/broker/publish/messages/dropped': 0,
        '$SYS/broker/publish/messages/received': 0,
        '$SYS/broker/publish/messages/sent': 0,
        '$SYS/broker/uptime': -1
    }

    if mosq_test.check_features(["INC_MEMTRACK"]):
        expected_payload['$SYS/broker/heap/current'] = -1
        expected_payload['$SYS/broker/heap/maximum'] = -1

    if payload != expected_payload:
        raise ValueError(f"/api/v1/systree payload\n{payload}\n{expected_payload}")


def check_sys_tree_missing(http_conn):
    http_conn.request("GET", "/api/v1/systree")
    response = http_conn.getresponse()
    if response.status != 404:
        raise ValueError(f"/api/v1/systree {response.status}")


mqtt_port, ws_port, http_port = mosq_test.get_port(3)
broker_config = BrokerConfig(
    allow_anonymous=True,
    listeners = [
        ListenerConfig(port=mqtt_port),
        ListenerConfig(
            port=http_port,
            protocol="http_api",
        ),
    ]
)
if mosq_test.check_features(["WITH_TLS", "WITH_UNIX_SOCKETS"]):
    broker_config.listeners.append(
        ListenerConfig(
            port=0,
            address=f"{mqtt_port}.sock",
            certfile=f"{ssl_dir}/server.crt",
            keyfile=f"{ssl_dir}/server.key",
        )
    )
if mosq_test.check_features(["WITH_WEBSOCKETS"]):
    broker_config.listeners.append(
        ListenerConfig(
            port=ws_port,
            protocol="websockets"
        )
    )

broker = MosquittoBroker(config=broker_config)
with broker:
    http_conn = http.client.HTTPConnection(f"localhost:{http_port}")

    # Bad request type
    http_conn.request("POST", "/api/badrequest")
    response = http_conn.getresponse()
    if response.status != 405:
        raise ValueError(f"/api/badrequest {response.status}")

    # Missing API
    http_conn.request("GET", "/api/missing")
    response = http_conn.getresponse()
    if response.status != 404:
        raise ValueError(f"/api/missing {response.status}")

    # Listeners API
    http_conn.request("GET", "/api/v1/listeners")
    response = http_conn.getresponse()
    if response.status != 200:
        raise ValueError(f"/api/v1/listeners {response.status}")
    payload = json.loads(response.read().decode('utf-8'))
    expected_payload = {
        "listeners": [{
            "port": mqtt_port,
            "protocol": "mqtt",
            "tls": False,
            "mtls": False,
            "allow_anonymous": True
        }, {
            "port": http_port,
            "protocol": "httpapi",
            "tls": False,
            "mtls": False,
            "allow_anonymous": True
        }]
    }

    if mosq_test.check_features(["WITH_TLS", "WITH_UNIX_SOCKETS"]):
        expected_payload["listeners"].append({
            "path": f"{mqtt_port}.sock",
            "protocol": "mqtt",
            "tls": True,
            "mtls": False,
            "allow_anonymous": True
        })

    if mosq_test.check_features(["WITH_WEBSOCKETS"]):
        expected_payload["listeners"].append({
            "port": ws_port,
            "protocol": "websockets",
            "tls": False,
            "mtls": False,
            "allow_anonymous": True
       })

    if payload != expected_payload:
        raise ValueError(f"/api/v1/listeners payload\n{payload}\n{expected_payload}")

    if mosq_test.check_features(["WITH_SYS_TREE"]):
        check_sys_tree(http_conn)
    else:
        check_sys_tree_missing(http_conn)

    # Version API
    http_conn.request("GET", "/api/v1/version")
    response = http_conn.getresponse()
    if response.status != 200:
        raise ValueError(f"Error: /api/v1/version {response.status}")
    payload = response.read().decode('utf-8')
    if not re.match(r'^\d+\.\d+\.\d+.*$', payload):
        raise ValueError(f"Error: /api/v1/version\n{payload}")
