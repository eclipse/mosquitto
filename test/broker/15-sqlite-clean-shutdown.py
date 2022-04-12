#!/usr/bin/env python3

# Check whether the sqlite plugin cleans everything up before closing - this
# means the WAL journal file will not exist when it has closed.

from mosq_test_helper import *
import json
import shutil
import sqlite_help

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
sqlite_help.write_config(conf_file, port)

rc = 1

sqlite_help.init(port)

proto_ver = 4
connect_packet = mosq_test.gen_connect("sqlite-clean-shutdown", proto_ver=4)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=4)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    # Check broker is running
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    sock.close()
except mosq_test.TestError:
    pass
finally:
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    (stdo, stde) = broker.communicate()

    os.remove(conf_file)
    rc = sqlite_help.cleanup(port)
    if rc:
        print(stde.decode('utf-8'))


exit(rc)
