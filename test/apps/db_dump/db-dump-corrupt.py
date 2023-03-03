#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(file, stderr, rc_expected):

    cmd = [
        mosq_test.get_build_root()+'/apps/db_dump/mosquitto_db_dump',
        f'{test_dir}/apps/db_dump/data/{file}'
    ]

    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1, encoding='utf-8')
    if res.stderr != stderr:
        print(res.stderr)
        raise mosq_test.TestError
    if res.returncode != rc_expected:
        print(file)
        print(res.returncode)
        raise mosq_test.TestError

do_test('missing.test-db', f"Error: Unable to open {test_dir}/apps/db_dump/data/missing.test-db\n", 0)
do_test('bad-magic.test-db', "Error: Unrecognised file format.\n", 1)
do_test('short.test-db', "Error: Corrupt persistent database.\n", 1)
do_test('bad-dbid-size.test-db', "Error: Incompatible database configuration (dbid size is 5 bytes, expected 8)", 1)
do_test('bad-chunk.test-db', 'Warning: Unsupported chunk "2816" of length 65696 in persistent database file at position 29. Ignoring.\n', 0)
do_test('v3-corrupt.test-db', "Error: Corrupt persistent database.\n", 1)
do_test('v4-corrupt.test-db', "Error: Corrupt persistent database.\n", 1)
do_test('v5-corrupt.test-db', "Error: Corrupt persistent database.\n", 1)
do_test('v6-corrupt.test-db', "Error: Corrupt persistent database.\n", 1)
do_test('v6-corrupt-client.test-db', "Error: Corrupt persistent database.\n", 1)
do_test('v6-corrupt-cmsg.test-db', "Error: Corrupt persistent database.\n", 1)
do_test('v6-corrupt-retain.test-db', "Error: Corrupt persistent database.\n", 1)
do_test('v6-corrupt-sub.test-db', "Error: Corrupt persistent database.\n", 1)
