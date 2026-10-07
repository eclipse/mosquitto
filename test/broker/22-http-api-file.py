#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker
import http.client
import json

mosq_test.require_features(["WITH_HTTP_API"])

def write_index(port):
    with open("index.html", 'w') as f:
        f.write("<html></html>")

mqtt_port, http_port = mosq_test.get_port(2)

broker_config = BrokerConfig(
    listeners=[
        ListenerConfig(port=mqtt_port),
        ListenerConfig(
            port=http_port,
            address="127.0.0.1",
            protocol="http_api",
            http_dir=Path("."),
        )
    ],
    allow_anonymous=True
)
write_index(mqtt_port)

broker = MosquittoBroker(config=broker_config)
broker.add_extra_file("index.html")
with broker:
    http_conn = http.client.HTTPConnection(f"localhost:{http_port}")

    # Bad request
    http_conn.request("POST", "/post")
    response = http_conn.getresponse()
    if response.status != 405:
        raise ValueError(f"Error: /post {response.status}")

    # Bad request
    http_conn.request("PUT", "/put")
    response = http_conn.getresponse()
    if response.status != 405:
        raise ValueError(f"Error: /put {response.status}")

    # Missing file
    http_conn.request("GET", "/missing")
    response = http_conn.getresponse()
    if response.status != 404:
        raise ValueError(f"Error: /api/missing {response.status}")

    # File not in dir
    http_conn.request("GET", "../../../../../../../../etc/passwd")
    response = http_conn.getresponse()
    if response.status != 404:
        raise ValueError(f"Error: ../../../../../../../../etc/passwd {response.status}")

    # Present file
    http_conn.request("GET", "/index.html")
    response = http_conn.getresponse()
    if response.status != 200:
        raise ValueError(f"Error: /index.html {response.status}")

    # Root
    http_conn.request("GET", "/")
    response = http_conn.getresponse()
    if response.status != 200:
        raise ValueError(f"Error: / {response.status}")
    payload = response.read().decode('utf-8')
    if payload != "<html></html>":
        raise ValueError(f"Error: / {payload}")
