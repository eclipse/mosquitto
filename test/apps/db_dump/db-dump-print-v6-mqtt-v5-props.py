#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(file, stdout):

    cmd = [
        mosq_test.get_build_root() + '/apps/db_dump/mosquitto_db_dump',
        f'{test_dir}/apps/db_dump/data/{file}'
    ]

    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, encoding='utf-8')
    if res.stdout != stdout:
        print(res.stdout)
        raise mosq_test.TestError

stdout = """Mosquitto DB dump
CRC: 0
DB version: 6
DB_CHUNK_CFG:
	Length: 16
	Shutdown: 1
	DB ID size: 8
	Last DB ID: 273732472648936
DB_CHUNK_BASE_MSG:
	Length: 187
	Store ID: 273732462748327
	Source Port: 1883
	Source MID: 1
	Topic: test-topic
	QoS: 1
	Retain: 0
	Payload Length: 7
	Expiry Time: 1669799825
	Payload: message
	Properties:
		Content type: text/plain
		Correlation data: 35636638653064652D356666612D346131302D393036622D346535623266393038363162
		Payload format indicator: 1
		Response topic: pub-response-topic
		User property: pub-key , pub-value
DB_CHUNK_BASE_MSG:
	Length: 132
	Store ID: 273732472648936
	Source Port: 0
	Source MID: 0
	Topic: will-topic
	QoS: 2
	Retain: 1
	Payload Length: 12
	Expiry Time: 1669799786
	Payload: will-payload
	Properties:
		Content type: text/plain
		Correlation data: 636F7272656C6174696F6E2D64617461
		Payload format indicator: 1
		Response topic: will-response-topic
		User property: key , value
DB_CHUNK_CLIENT:
	Length: 32
	Client ID: clientid
	Last MID: 1
	Session expiry time: 1669799784
	Session expiry interval: 60
DB_CHUNK_CLIENT_MSG:
	Length: 27
	Client ID: clientid
	Store ID: 273732462748327
	MID: 1
	QoS: 1
	Retain: 0
	Direction: 1
	State: 11
	Dup: 0
	Subscription identifier: 42
DB_CHUNK_SUB:
	Length: 30
	Client ID: clientid
	Topic: test-topic
	QoS: 1
	Subscription ID: 42
	Options: 0x00
DB_CHUNK_RETAIN:
	Length: 8
	Store ID: 273732472648936
"""
do_test('v6-mqtt-v5-props.test-db', stdout)
