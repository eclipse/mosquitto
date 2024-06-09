#!/usr/bin/env python3

from mosq_test_helper import *
import json
import shutil

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous false\n")
        f.write(f"plugin {mosq_test.get_build_root()}/plugins/dynamic-security/mosquitto_dynamic_security.so\n")
        f.write("plugin_opt_config_file %d/dynamic-security.json\n" % (port))


port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

try:
    os.mkdir(str(port))
except FileExistsError:
    pass

rc = 1
connect_packet = mosq_test.gen_connect("ctrl-test", username="admin", password="adminadminadmin")
connack_packet = mosq_test.gen_connack(rc=0)

env = os.environ
env["MOSQUITTO_DYNSEC_PASSWORD"] = "adminadminadmin"
broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port, env=env, timeout=3)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    rc = 0
    sock.close()
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    try:
        os.remove(f"{port}/dynamic-security.json")
    except FileNotFoundError:
        pass
    try:
        os.remove(f"{port}/dynamic-security.json.pw")
    except FileNotFoundError:
        pass
    os.rmdir(f"{port}")
    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))


exit(rc)
