#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(file, stdout):

    cmd = [
        mosq_test.get_build_root()+'/apps/db_dump/mosquitto_db_dump',
        f'{test_dir}/apps/db_dump/data/{file}'
    ]

    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1, encoding='utf-8')
    if res.stdout != stdout:
        raise mosq_test.TestError

v3_empty = """Mosquitto DB dump
CRC: 0
DB version: 3
DB_CHUNK_CFG:
	Length: 10
	Shutdown: 1
	DB ID size: 8
	Last DB ID: 51
"""
do_test('v3-empty.test-db', v3_empty)

v4_empty = """Mosquitto DB dump
CRC: 0
DB version: 4
DB_CHUNK_CFG:
	Length: 10
	Shutdown: 1
	DB ID size: 8
	Last DB ID: 102
"""
do_test('v4-empty.test-db', v4_empty)

v5_empty = """Mosquitto DB dump
CRC: 0
DB version: 5
DB_CHUNK_CFG:
	Length: 16
	Shutdown: 1
	DB ID size: 8
	Last DB ID: 52
"""
do_test('v5-empty.test-db', v5_empty)

v6_empty = """Mosquitto DB dump
CRC: 0
DB version: 6
DB_CHUNK_CFG:
	Length: 16
	Shutdown: 1
	DB ID size: 8
	Last DB ID: 208485212291791
"""
do_test('v6-empty.test-db', v6_empty)
