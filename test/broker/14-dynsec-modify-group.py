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

def command_check(sock, command_payload, expected_response, msg=""):
    command_packet = mosq_test.gen_publish(topic="$CONTROL/dynamic-security/v1", qos=0, payload=json.dumps(command_payload))
    sock.send(command_packet)
    response = json.loads(mosq_test.read_publish(sock))
    if response != expected_response:
        print(msg)
        print(expected_response)
        print(response)
        raise ValueError(response)



port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

create_client_command = { "commands": [{
            "command": "createClient", "username": "user_one",
            "password": "password", "clientid": "cid",
            "textname": "Name", "textdescription": "Description",
            "correlationData": "2" }]
}
create_client_response = {'responses': [{'command': 'createClient', 'correlationData': '2'}]}

create_group_command = { "commands": [{
    "command": "createGroup", "groupname": "group_one",
    "textname": "Name", "textdescription": "Description",
    "rolename": "", "correlationData": "2" }]
}
create_group_response = {'responses': [{'command': 'createGroup', 'correlationData': '2'}]}

create_role_command = { "commands": [
    {
        "command": "createRole", "rolename": "role_one",
        "textname": "Name", "textdescription": "Description",
        "acls":[], "correlationData": "2"
    },
    {
        "command": "createRole", "rolename": "role_two",
        "textname": "Name", "textdescription": "Description",
        "acls":[], "correlationData": "3"
    }
    ]
}
create_role_response = {'responses': [
    {'command': 'createRole', 'correlationData': '2'},
    {'command': 'createRole', 'correlationData': '3'}
    ]}

modify_group_command1 = { "commands": [{
    "command": "modifyGroup", "groupname": "group_one",
    "textname": "Modified name", "textdescription": "Modified description",
    "roles":[{'rolename':'role_one'}],
    "clients":[{'username':'user_one'}],
    "correlationData": "3" }]
}
modify_group_response1 = {'responses': [{'command': 'modifyGroup', 'correlationData': '3'}]}

modify_group_command2 = { "commands": [{
    "command": "modifyGroup", "groupname": "group_one",
    "textname": "Modified name", "textdescription": "Modified description",
    "roles":[
        {'rolename':'role_one', 'priority':99},
        {'rolename':'role_two', 'priority':87}
    ],
    "clients":[],
    "correlationData": "3" }]
}
modify_group_response2 = {'responses': [{'command': 'modifyGroup', 'correlationData': '3'}]}

modify_group_command3 = { "commands": [{
    "command": "modifyGroup", "groupname": "group_one",
    "textname": "Modified name", "textdescription": "Modified description",
    "roles":[],
    "clients":[],
    "correlationData": "3" }]
}
modify_group_response3 = {'responses': [{'command': 'modifyGroup', 'correlationData': '3'}]}


get_group_command1 = { "commands": [{
    "command": "getGroup", "groupname": "group_one"}]}
get_group_response1 = {'responses':[{'command': 'getGroup', 'data': {'group': {'groupname': 'group_one',
    'textname': 'Name', 'textdescription': 'Description',
    'clients':[],
    'roles': []}}}]}

get_group_command2 = { "commands": [{
    "command": "getGroup", "groupname": "group_one"}]}
get_group_response2 = {'responses':[{'command': 'getGroup', 'data': {'group': {'groupname': 'group_one',
    'textname': 'Modified name', 'textdescription': 'Modified description',
    'clients':[{'username':'user_one'}],
    'roles': [{'rolename':'role_one'}]}}}]}

get_group_command3 = { "commands": [{
    "command": "getGroup", "groupname": "group_one"}]}
get_group_response3 = {'responses':[{'command': 'getGroup', 'data': {'group': {'groupname': 'group_one',
    'textname': 'Modified name', 'textdescription': 'Modified description',
    'clients':[],
    'roles': [
        {'rolename':'role_one', 'priority':99},
        {'rolename':'role_two', 'priority':87}
    ]}}}]}

get_group_command4 = { "commands": [{
    "command": "getGroup", "groupname": "group_one"}]}
get_group_response4 = {'responses':[{'command': 'getGroup', 'data': {'group': {'groupname': 'group_one',
    'textname': 'Modified name', 'textdescription': 'Modified description',
    'clients':[],
    'roles': []}}}]}



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

    # Create client
    command_check(sock, create_client_command, create_client_response)

    # Create group
    command_check(sock, create_group_command, create_group_response)

    # Create role
    command_check(sock, create_role_command, create_role_response)

    # Get group
    command_check(sock, get_group_command1, get_group_response1, "get group 1")

    # Modify group
    command_check(sock, modify_group_command1, modify_group_response1)

    # Get group
    command_check(sock, get_group_command2, get_group_response2, "get group 2a")

    # Kill broker and restart, checking whether our changes were saved.
    broker.terminate()
    broker.wait()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    # Get group
    command_check(sock, get_group_command2, get_group_response2, "get group 2b")

    # Modify group
    command_check(sock, modify_group_command2, modify_group_response2)

    # Get group
    command_check(sock, get_group_command3, get_group_response3, "get group 3")

    # Modify group
    command_check(sock, modify_group_command3, modify_group_response3)

    # Get group
    command_check(sock, get_group_command4, get_group_response4, "get group 4")

    rc = 0

    sock.close()
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    try:
        os.remove(f"{port}/dynamic-security.json")
        pass
    except FileNotFoundError:
        pass
    os.rmdir(f"{port}")
    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))


exit(rc)
