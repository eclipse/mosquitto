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

create_role_command = { "commands": [{
    "command": "createRole", "rolename": "role_one",
    "textname": "Name", "textdescription": "Description",
    "acls":[
        {
            "acltype": "publishClientSend",
            "allow": True,
            "topic": "topic/#",
            "priority": 8
        },
        {
            "acltype": "publishClientSend",
            "allow": True,
            "topic": "topic/2/#",
            "priority": 9
        }
    ], "correlationData": "2" }]
}
create_role_response = {'responses': [{'command': 'createRole', 'correlationData': '2'}]}

modify_role_command = { "commands": [{
    "command": "modifyRole", "rolename": "role_one",
    "textname": "Modified name", "textdescription": "Modified description",
    "acls":[
        {
            "acltype": "publishClientReceive",
            "allow": True,
            "topic": "topic/#",
            "priority": 2
        },
        {
            "acltype": "publishClientReceive",
            "allow": True,
            "topic": "topic/2/#",
            "priority": 1
        }
    ],
    "correlationData": "3" }]
}
modify_role_response = {'responses': [{'command': 'modifyRole', 'correlationData': '3'}]}


get_role_command1 = { "commands": [{"command": "getRole", "rolename": "role_one"}]}
get_role_response1 = {'responses':[{'command': 'getRole', 'data': {'role': {'rolename': 'role_one',
    'textname': 'Name', 'textdescription': 'Description',
    'acls': [
        {
            "acltype": "publishClientSend",
            "topic": "topic/2/#",
            "allow": True,
            "priority": 9
        },
        {
            "acltype": "publishClientSend",
            "topic": "topic/#",
            "allow": True,
            "priority": 8
        }
    ]}}}]}

get_role_command2 = { "commands": [{
    "command": "getRole", "rolename": "role_one"}]}
get_role_response2 = {'responses':[{'command': 'getRole', 'data': {'role': {'rolename': 'role_one',
    'textname': 'Modified name', 'textdescription': 'Modified description',
    'acls': [
        {
            "acltype": "publishClientReceive",
            "topic": "topic/#",
            "allow": True,
            "priority": 2
        },
        {
            "acltype": "publishClientReceive",
            "topic": "topic/2/#",
            "allow": True,
            "priority": 1
        }
    ]}}}]}

rc = 1
keepalive = 10
connect_packet = mosq_test.gen_connect("ctrl-test", keepalive=keepalive, username="admin", password="admin")
connack_packet = mosq_test.gen_connack(rc=0)

mid = 2
subscribe_packet = mosq_test.gen_subscribe(mid, "$CONTROL/#", 1)
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

    # Add role
    command_check(sock, create_role_command, create_role_response)

    # Get role
    command_check(sock, get_role_command1, get_role_response1)

    # Modify role
    command_check(sock, modify_role_command, modify_role_response)

    # Get role
    command_check(sock, get_role_command2, get_role_response2)

    # Kill broker and restart, checking whether our changes were saved.
    broker.terminate()
    broker.wait()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    # Get role
    command_check(sock, get_role_command2, get_role_response2)

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
