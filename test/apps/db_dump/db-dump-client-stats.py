#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(file, counts):
    stdout = f"SC: {counts[0]} " + \
        f"SS: {counts[1]} " + \
        f"MC: {counts[2]} " + \
        f"MS: {counts[3]} " + \
        f"  {counts[4]}\n"

    cmd = [
        mosq_test.get_build_root()+'/apps/db_dump/mosquitto_db_dump',
        '--client-stats',
        f'{test_dir}/apps/db_dump/data/{file}'
    ]

    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1, encoding='utf-8')
    if res.stdout != stdout:
        print(res.stdout)
        print(stdout)
        raise mosq_test.TestError

do_test('v6-single-all.test-db', [1,27,1,111,'single-all'])
