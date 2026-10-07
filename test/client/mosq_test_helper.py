import inspect, os, sys

# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_paths
import mosq_test
import mqtt5_opts
import mqtt5_props
import mqtt5_rc
import mqtt_packets
from mosquitto_broker import MosquittoBroker

import socket
import ssl
import struct
import subprocess
import time
import errno

from pathlib import Path

source_dir = Path(__file__).resolve().parent

def client_run(cmd_path, args, stderr_expected, rc_expected):
    port = mosq_test.get_port()

    env = {
        'XDG_CONFIG_HOME':'/tmp/missing'
    }
    env = mosq_test.env_add_ld_library_path(env)
    cmd = [cmd_path] + args

    client = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if client.returncode != rc_expected:
        raise mosq_test.TestError(client.returncode)
    if stderr_expected is not None and stderr_expected not in client.stderr:
        raise mosq_test.TestError(f"Got:\n{client.stderr}\nExpected:\n{stderr_expected}")