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
connect_packet = mqtt_packets.gen_connect("ctrl-test", username="admin", password="admin")
connack_packet = mqtt_packets.gen_connack(rc=0)

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
    mosq_test.terminate_broker(broker)
    broker_terminate_rc = 0
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        broker_terminate_rc = 1
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

    check_details(sock, 2, 1, 3, 7)

    rc = broker_terminate_rc

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
    mosq_test.terminate_broker(broker)
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    if rc:
        print(mosq_test.broker_log(broker))


exit(rc)
