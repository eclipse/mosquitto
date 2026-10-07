#!/usr/bin/env python3

from mosq_test_helper import *
from dynsec_helper import *
import json
import shutil

mosq_test.require_features(["WITH_CONTROL", "WITH_PLUGINS", "WITH_PLUGIN_DYNAMIC_SECURITY", "WITH_TLS"])

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write(f"plugin {mosq_paths.plugin_dynamic_security}\n")
        f.write(f"plugin_opt_config_file {Path(str(port), 'dynamic-security.json')}\n")


port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

add_client_command = { "commands": [{
            "command": "createClient", "username": "user_one",
            "password": "password", "clientid": "cid",
            "textname": "Name", "textdescription": "Description",
            "rolename": "", "correlationData": "2" }]
}
add_client_response = {'responses': [{'command': 'createClient', 'correlationData': '2'}]}
add_client_repeat_response = {'responses':[{"command":"createClient","error":"Client already exists", "correlationData":"2"}]}

get_client_command = { "commands": [{
            "command": "getClient", "username": "user_one"}]}
get_client_response1 = {'responses':[{'command': 'getClient', 'data': {'client': {'username': 'user_one', 'clientid': 'cid',
            'textname': 'Name', 'textdescription': 'Description', 'groups': [], 'roles': [], 'connections': []}}}]}
get_client_response2 = {'responses':[{'command': 'getClient', 'data': {'client': {'username': 'user_one', 'clientid': 'cid',
            'textname': 'Name', 'textdescription': 'Description', 'disabled':True, 'groups': [], 'roles': [], 'connections': []}}}]}

disable_client_command = { "commands": [{
            "command": "disableClient", "username": "user_one"}]}
disable_client_response = {'responses':[{'command': 'disableClient'}]}

enable_client_command = { "commands": [{
            "command": "enableClient", "username": "user_one"}]}
enable_client_response = {'responses':[{'command': 'enableClient'}]}

rc = 1
connect_packet = mqtt_packets.gen_connect("ctrl-test", username="admin", password="admin")
connack_packet = mqtt_packets.gen_connack(rc=0)

client_connect_packet = mqtt_packets.gen_connect("cid", username="user_one", password="password")
client_connack_packet1 = mqtt_packets.gen_connack(rc=5)
client_connack_packet2 = mqtt_packets.gen_connack(rc=0)

mid = 2
subscribe_packet = mqtt_packets.gen_subscribe(mid, "$CONTROL/dynamic-security/#", 1)
suback_packet = mqtt_packets.gen_suback(mid, 1)

try:
    os.mkdir(str(port))
    shutil.copyfile(str(Path(__file__).resolve().parent / "dynamic-security-init.json"), "%d/dynamic-security.json" % (port))
except FileExistsError:
    pass

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    # Add client
    command_check(sock, add_client_command, add_client_response)

    # Get client
    command_check(sock, get_client_command, get_client_response1)

    # Disable client
    command_check(sock, disable_client_command, disable_client_response)

    # Get client - should be disabled
    command_check(sock, get_client_command, get_client_response2)

    # Try to log in - should fail
    client_sock = mosq_test.do_client_connect(client_connect_packet, client_connack_packet1, timeout=5, port=port)

    # Enable client
    command_check(sock, enable_client_command, enable_client_response)

    # Get client - should be enabled
    command_check(sock, get_client_command, get_client_response1)

    # Try to log in - should succeed
    client_sock = mosq_test.do_client_connect(client_connect_packet, client_connack_packet2, timeout=5, port=port)
    client_sock.close()

    check_details(sock, 2, 0, 1, 3)

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
    os.rmdir(f"{port}")
    mosq_test.terminate_broker(broker)
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    if rc:
        print(mosq_test.broker_log(broker))


exit(rc)
