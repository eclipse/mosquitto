#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker
import http.client
import json
import re

mosq_test.require_features(["WITH_HTTP_API", "WITH_PLUGINS", "WITH_PLUGIN_ACL_FILE"])

mqtt_port, http_port = mosq_test.get_port(2)
aclfile = f"{http_port}.acl"

broker_config = BrokerConfig(
    listeners=[
        ListenerConfig(port=mqtt_port),
        ListenerConfig(
            port=http_port,
            protocol="http_api",
        )
    ],
    plugins=[
        PluginConfig(
            path=mosq_paths.plugin_acl_file,
            options={
                'plugin_opt_acl_file': aclfile
            }
        )
    ],
    allow_anonymous=True,
)
broker = MosquittoBroker(config=broker_config)
broker.add_extra_file(aclfile)

with open(aclfile, "wt") as f:
    f.write("topic read /api/v1/version")
with broker:
    http_conn = http.client.HTTPConnection(f"localhost:{http_port}")

    # systree API
    http_conn.request("GET", "/api/v1/systree")
    response = http_conn.getresponse()
    if response.status != 401:
        raise ValueError(f"/api/v1/systree {response.status}")
    payload = response.read().decode('utf-8')
    if payload != "Not authorised\n":
        raise ValueError(f"Error: {payload}")

    # Version API
    http_conn.request("GET", "/api/v1/version")
    response = http_conn.getresponse()
    if response.status != 200:
        raise ValueError(f"Error: /api/v1/version {response.status}")
    payload = response.read().decode('utf-8')
    if not re.match(r'^\d+\.\d+\.\d+.*$', payload):
        raise ValueError(f"Error: /api/v1/version\n{payload}")
