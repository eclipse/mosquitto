#!/usr/bin/env python3

from mosq_test_helper import *

rc = 1

client_args = sys.argv[1:]
env = dict(os.environ)
env['LD_LIBRARY_PATH'] = '../../lib:../../lib/cpp'
try:
    pp = env['PYTHONPATH']
except KeyError:
    pp = ''
env['PYTHONPATH'] = '../../lib/python:'+pp

client = mosq_test.start_client(filename=sys.argv[1].replace('/', '-'), cmd=client_args, env=env)
if mosq_test.wait_for_subprocess(client):
    print("test client not finished")
    rc=1
else:
    rc=client.returncode
exit(rc)
