import inspect, os, sys

# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test
import mqtt5_props

import socket
import ssl
import struct
import subprocess
import time


from pathlib import Path

source_dir = Path(__file__).resolve().parent
ssl_dir = source_dir.parent / "ssl"
