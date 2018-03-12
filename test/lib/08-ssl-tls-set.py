#!/usr/bin/env python

import inspect
import os
import sys

# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

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
client.wait()

rc = client.returncode

exit(rc)
