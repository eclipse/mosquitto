#!/usr/bin/env python3
# Test whether a broker handles cleansession and local_cleansession correctly on bridges

from collections import namedtuple

from mosq_test_helper import *

(port_a_listen, port_b_listen) = mosq_test.get_port(2)
subprocess.run([f'{Path(__file__).resolve().parent}/06-bridge-clean-session-core.py', str(port_a_listen), str(port_b_listen), "False", "False"])
