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
broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port, timeout=3)

with open(f"{port}/dynamic-security.json.pw", "r") as f:
    data = f.readlines()

admin_pw = data[0].split(" ")[1].strip()
user_pw = data[1].split(" ")[1].strip()

try:
    # Admin user
    connect_packet = mosq_test.gen_connect("ctrl-test", username="admin", password=admin_pw)
    connack_packet = mosq_test.gen_connack(rc=0)
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)

    # Subscribe should be allowed
    mid = 2
    subscribe_packet = mosq_test.gen_subscribe(mid, "$CONTROL/dynamic-security/#", 1)
    suback_packet = mosq_test.gen_suback(mid, 1)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "admin suback")
    sock.close()

    # Basic user
    connect_packet = mosq_test.gen_connect("ctrl-test", username="democlient", password=user_pw)
    connack_packet = mosq_test.gen_connack(rc=0)
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)

    # Subscribe should not be allowed
    mid = 2
    subscribe_packet = mosq_test.gen_subscribe(mid, "$CONTROL/dynamic-security/#", 1)
    suback_packet = mosq_test.gen_suback(mid, 128)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "user suback")
    sock.close()

    rc = 0
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
