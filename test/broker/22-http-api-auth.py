#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker
import base64
import http.client
import json
import re

mosq_test.require_features(["WITH_HTTP_API", "WITH_PLUGINS", "WITH_PLUGIN_PASSWORD_FILE", "WITH_TLS"])

mqtt_port, http_port = mosq_test.get_port(2)
broker_config = BrokerConfig(
    listeners = [
        ListenerConfig(port=mqtt_port),
        ListenerConfig(
            port=http_port,
            protocol="http_api",
        )
    ],
    plugins = [
        PluginConfig(
            path=mosq_paths.plugin_password_file,
            options={
                "plugin_opt_password_file": Path(__file__).resolve().parent / "22-http-api-auth.pwfile",
            }
        )
    ]
)
broker = MosquittoBroker(config=broker_config)
with broker:
    http_conn = http.client.HTTPConnection(f"localhost:{http_port}")

    # No auth
    http_conn.request("GET", "/api/v1/version")
    response = http_conn.getresponse()
    if response.status != 401:
        raise ValueError(f"Error: /api/v1/version {response.status}")
    payload = response.read().decode('utf-8')
    if payload != "Not authorised\n":
        raise ValueError(f"Error: {payload}")

    # Bad auth
    credentials = "user:invalid"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_credentials}"
    }
    http_conn.request("GET", "/api/v1/version", headers=headers)
    response = http_conn.getresponse()
    if response.status != 401:
        raise ValueError(f"Error: /api/v1/version {response.status}")
    payload = response.read().decode('utf-8')
    if payload != "Not authorised\n":
        raise ValueError(f"Error: {payload}")

    # Good auth
    credentials = "user:password"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_credentials}"
    }
    http_conn.request("GET", "/api/v1/version", headers=headers)
    response = http_conn.getresponse()
    if response.status != 200:
        raise ValueError(f"Error: /api/v1/version {response.status}")
