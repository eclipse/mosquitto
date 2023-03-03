#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(file, counts):
    stdout = f"DB_CHUNK_CFG:        {counts[0]}\n" + \
        f"DB_CHUNK_BASE_MSG:   {counts[1]}\n" + \
        f"DB_CHUNK_CLIENT_MSG: {counts[2]}\n" + \
        f"DB_CHUNK_RETAIN:     {counts[3]}\n" + \
        f"DB_CHUNK_SUB:        {counts[4]}\n" + \
        f"DB_CHUNK_CLIENT:     {counts[5]}\n"

    cmd = [
        mosq_test.get_build_root()+'/apps/db_dump/mosquitto_db_dump',
            '--stats',
            f'{test_dir}/apps/db_dump/data/{file}'
    ]

    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1, encoding='utf-8')
    if res.stdout != stdout:
        print(res.stdout)
        raise mosq_test.TestError

do_test('v3-empty.test-db', [1,0,0,0,0,0])
do_test('v4-empty.test-db', [1,0,0,0,0,0])
do_test('v5-empty.test-db', [1,0,0,0,0,0])
do_test('v6-empty.test-db', [1,0,0,0,0,0])

do_test('v4-single-client.test-db', [1,0,0,0,0,1])
do_test('v6-single-client.test-db', [1,0,0,0,0,1])

do_test('v4-single-retain.test-db', [1,1,0,1,0,0])
do_test('v6-single-retain.test-db', [1,1,0,1,0,0])

do_test('v4-single-sub.test-db', [1,0,0,0,1,1])
do_test('v6-single-sub.test-db', [1,0,0,0,1,1])

do_test('v4-single-cmsg.test-db', [1,1,1,0,1,1])
do_test('v6-single-cmsg.test-db', [1,1,1,0,1,1])

do_test('v6-single-all.test-db', [1,1,1,1,1,1])
