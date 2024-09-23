#!/usr/bin/env python3

import json
from mosq_test_helper import *

def do_test(file, json_expected):

    cmd = [
        mosq_test.get_build_root() + '/apps/db_dump/mosquitto_db_dump',
        '--json',
        f'{test_dir}/apps/db_dump/data/{file}'
    ]

    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, encoding='utf-8')
    json_result = json.loads(res.stdout)
    if json.dumps(json_result) != json.dumps(json_expected):
        print(json.dumps(json_result))
        print(json.dumps(json_expected))
        raise mosq_test.TestError

json_expected = {
    "base-messages": [{
        "storeid": 273732462748327,
        "expiry-time": 1669799825,
        "source-mid": 1,
        "source-port": 1883,
        "qos": 1,
        "retain": 0,
        "topic": "test-topic",
        "clientid": "auto-1F56F09A-97D3-2395-8B77-185E54E0A83C",
        "payload": "bWVzc2FnZQ==", # "message"
        "properties": [{
            "identifier": "content-type",
            "value": "text/plain"
        }, {
            "identifier": "correlation-data",
            "value": "35636638653064652D356666612D346131302D393036622D346535623266393038363162"
        }, {
            "identifier": "payload-format-indicator",
            "value": 1
        }, {
            "identifier": "response-topic",
            "value": "pub-response-topic"
        }, {
            "identifier": "user-property",
            "name": "pub-key",
            "value": "pub-value"
        }]
    },{
        "storeid": 273732472648936,
        "expiry-time": 1669799786,
        "source-mid": 0,
        "source-port": 0,
        "qos": 2,
        "retain": 1,
        "topic": "will-topic",
        "clientid": "clientid",
        "payload": "d2lsbC1wYXlsb2Fk",
        "properties": [{
            "identifier": "content-type",
            "value": "text/plain"
        }, {
            "identifier": "correlation-data",
            "value": "636F7272656C6174696F6E2D64617461"
        }, {
            "identifier": "payload-format-indicator",
            "value": 1
        }, {
            "identifier": "response-topic",
            "value": "will-response-topic"
        }, {
            "identifier": "user-property",
            "name": "key",
            "value": "value"
        }]
    }],

    "clients": [{
        "clientid": "clientid",
        "session-expiry-time": 1669799784,
        "session-expiry-interval": 60,
        "last-mid": 1,
        "listener-port": 0
    }],

    "client-messages": [{
        "clientid": "clientid",
        "storeid": 42,
        "mid": 1,
        "qos": 1,
        "state": 11,
        "retain-dup": 0,
        "direction": 1,
        "subscription-identifier": 42
    }],

    "retained-messages": [{
        "storeid": 273732472648936
        }],
    "subscriptions": [{
        "clientid": "clientid",
        "topic": "test-topic",
        "qos": 1,
        "options": 0,
        "identifier": 42
    }]
}

do_test('v6-mqtt-v5-props.test-db', json_expected)
