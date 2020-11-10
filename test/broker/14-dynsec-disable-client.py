#!/usr/bin/env python3

from mosq_test_helper import *
import json
import shutil

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("plugin ../../plugins/dynamic-security/mosquitto_dynamic_security.so\n")
        f.write("plugin_opt_config_file %d/dynamic-security.json\n" % (port))

def command_check(sock, command_payload, expected_response):
    command_packet = mosq_test.gen_publish(topic="$CONTROL/dynamic-security/v1", qos=0, payload=json.dumps(command_payload))
    sock.send(command_packet)
    response = json.loads(mosq_test.read_publish(sock))
    if response != expected_response:
        print(expected_response)
        print(response)
        raise ValueError(response)



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
    'textname': 'Name', 'textdescription': 'Description', 'groups': [], 'roles': []}}}]}
get_client_response2 = {'responses':[{'command': 'getClient', 'data': {'client': {'username': 'user_one', 'clientid': 'cid',
    'textname': 'Name', 'textdescription': 'Description', 'disabled':True, 'groups': [], 'roles': []}}}]}

disable_client_command = { "commands": [{
            "command": "disableClient", "username": "user_one"}]}
disable_client_response = {'responses':[{'command': 'disableClient'}]}

enable_client_command = { "commands": [{
            "command": "enableClient", "username": "user_one"}]}
enable_client_response = {'responses':[{'command': 'enableClient'}]}

rc = 1
keepalive = 10
connect_packet = mosq_test.gen_connect("ctrl-test", keepalive=keepalive, username="admin", password="admin")
connack_packet = mosq_test.gen_connack(rc=0)

client_connect_packet = mosq_test.gen_connect("cid", keepalive=keepalive, username="user_one", password="password")
client_connack_packet1 = mosq_test.gen_connack(rc=5)
client_connack_packet2 = mosq_test.gen_connack(rc=0)

mid = 2
subscribe_packet = mosq_test.gen_subscribe(mid, "$CONTROL/dynamic-security/#", 1)
suback_packet = mosq_test.gen_suback(mid, 1)

try:
    os.mkdir(str(port))
    shutil.copyfile("dynamic-security-init.json", "%d/dynamic-security.json" % (port))
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
    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))


exit(rc)
