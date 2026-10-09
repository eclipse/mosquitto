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

create_role_command = { "commands": [{'command': 'createRole', 'correlationData': '3',
    "rolename": "basic", "acls":[
    {"acltype":"publishClientSend", "topic": "out/#", "priority":3, "allow": True}], "textname":"name", "textdescription":"desc"
    }]}
create_role_response = {'responses': [{'command': 'createRole', 'correlationData': '3'}]}

add_role_to_group_command = { "commands": [{'command': 'addGroupRole', 'correlationData': '4',
    "groupname": "group_one", "rolename": "basic"
    }]}
add_role_to_group_response = {'responses': [{'command': 'addGroupRole', 'correlationData': '4'}]}

create_client_command = { "commands": [{
            "command": "createClient", "username": "user_one",
            "password": "password", "clientid": "cid",
            "textname": "Name", "textdescription": "description",
            "rolename": "", "correlationData": "2" }]}
create_client_response = {'responses':[{"command":"createClient","correlationData":"2"}]}

create_client2_command = { "commands": [{
            "command": "createClient", "username": "user_two",
            "password": "password",
            "textname": "Name", "textdescription": "description",
            "rolename": "", "correlationData": "1" }]}
create_client2_response = {'responses':[{"command":"createClient","correlationData":"1"}]}

create_group_command = { "commands": [{
            "command": "createGroup", "groupname": "group_one",
            "textname": "Name", "textdescription": "description",
            "correlationData":"3"}]}
create_group_response = {'responses':[{"command":"createGroup","correlationData":"3"}]}
create_group_repeat_response = {'responses':[{"command":"createGroup","error":"Group already exists","correlationData":"3"}]}

create_group2_command = { "commands": [{
            "command": "createGroup", "groupname": "group_two",
            "textname": "Name", "textdescription": "description",
            "correlationData":"30"}]}
create_group2_response = {'responses':[{"command":"createGroup","correlationData":"30"}]}

list_groups_command = { "commands": [{
            "command": "listGroups", "verbose": False, "correlationData": "10"}]}
list_groups_response = {'responses':[{"command": "listGroups", "data":{"totalCount":2, "groups":["group_one","group_two"]},"correlationData":"10"}]}

list_groups_verbose_command = { "commands": [{
            "command": "listGroups", "verbose": True, "correlationData": "15"}]}
list_groups_verbose_response = {'responses':[{'command': 'listGroups', 'data': {"totalCount":2, 'groups':[
    {'groupname': 'group_one', 'textname': 'Name', 'textdescription': 'description', 'clients': [
    {"username":"user_one"}, {"username":"user_two"}], "roles":[{'rolename':'basic'}]},
    {'groupname': 'group_two', 'textname': 'Name', 'textdescription': 'description', 'clients': [
    {"username":"user_one"}], "roles":[]}
    ]},
    'correlationData': '15'}]}

list_clients_verbose_command = { "commands": [{
            "command": "listClients", "verbose": True, "correlationData": "20"}]}
list_clients_verbose_response = {'responses':[{"command": "listClients", "data":{"totalCount":3, "clients":[
            {'username': 'admin', 'textname': 'Dynsec admin user', 'roles': [{'rolename': 'admin'}], 'groups': [], 'connections': [{'address': '127.0.0.1'}]},
            {"username":"user_one", "clientid":"cid", "textname":"Name", "textdescription":"description",
             "groups":[{"groupname":"group_one"}, {"groupname":"group_two"}], "roles":[], 'connections': []},
            {"username":"user_two", "textname":"Name", "textdescription":"description",
             "groups":[{"groupname":"group_one"}], "roles":[],  'connections': []},
            ]}, "correlationData":"20"}]}

get_group_command = { "commands": [{"command": "getGroup", "groupname":"group_one"}]}
get_group_response = {'responses':[{'command': 'getGroup', 'data': {'group': {'groupname': 'group_one',
    'textname':'Name', 'textdescription':'description', 'clients': [{"username":"user_one"}, {"username":"user_two"}], 'roles': [{'rolename':'basic'}]
        }}}]}

add_client_to_group_command = {"commands": [{"command":"addGroupClient", "username":"user_one",
            "groupname": "group_one", "correlationData":"1234"}]}
add_client_to_group_response = {'responses':[{'command': 'addGroupClient', 'correlationData': '1234'}]}
add_duplicate_client_to_group_response = {'responses':[{'command': 'addGroupClient', 'error':'Client is already in this group', 'correlationData': '1234'}]}

add_client_to_group2_command = {"commands": [{"command":"addGroupClient", "username":"user_one",
            "groupname": "group_two", "correlationData":"1234"}]}
add_client_to_group2_response = {'responses':[{'command': 'addGroupClient', 'correlationData': '1234'}]}

add_client2_to_group_command = {"commands": [{"command":"addGroupClient", "username":"user_two",
            "groupname": "group_one", "correlationData":"1235"}]}
add_client2_to_group_response = {'responses':[{'command': 'addGroupClient', 'correlationData': '1235'}]}

remove_client_from_group_command = {"commands": [{"command":"removeGroupClient", "username":"user_one",
            "groupname": "group_one", "correlationData":"4321"}]}
remove_client_from_group_response = {'responses':[{'command': 'removeGroupClient', 'correlationData': '4321'}]}

delete_group_command = {"commands": [{"command":"deleteGroup", "groupname":"group_two", "correlationData":"5678"}]}
delete_group_response = {'responses':[{"command":"deleteGroup", "correlationData":"5678"}]}

delete_client_command = {"commands": [{"command": "deleteClient", "username": "user_one"}]}
delete_client_response = {'responses': [{'command': 'deleteClient'}]}

get_group_after_delete_client_command = {"commands": [{"command": "getGroup", "groupname": "group_one"}]}
get_group_after_delete_client_response = {"responses": [{"command": "getGroup", "data": {"group": {
    "groupname": "group_one", "textname": "Name", "textdescription": "description",
    "clients": [{"username": "user_two"}], "roles": [{"rolename": "basic"}]}}}]}

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

    # Add role
    command_check(sock, create_role_command, create_role_response)

    # Add client
    command_check(sock, create_client_command, create_client_response)
    command_check(sock, create_client2_command, create_client2_response)

    # Add group
    command_check(sock, create_group2_command, create_group2_response)
    command_check(sock, create_group_command, create_group_response)

    # Add client to group
    command_check(sock, add_client_to_group_command, add_client_to_group_response)
    command_check(sock, add_client_to_group2_command, add_client_to_group2_response)
    command_check(sock, add_client2_to_group_command, add_client2_to_group_response)
    command_check(sock, add_client_to_group_command, add_duplicate_client_to_group_response)

    # Add role to group
    command_check(sock, add_role_to_group_command, add_role_to_group_response)

    # Get group
    command_check(sock, get_group_command, get_group_response)

    # List groups non-verbose
    command_check(sock, list_groups_command, list_groups_response)

    # List groups verbose
    command_check(sock, list_groups_verbose_command, list_groups_verbose_response, "list groups")

    # List clients verbose
    command_check(sock, list_clients_verbose_command, list_clients_verbose_response)

    # Kill broker and restart, checking whether our changes were saved.
    mosq_test.terminate_broker(broker)
    broker_terminate_rc = 0
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        broker_terminate_rc = 1
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    # Add duplicate group
    command_check(sock, create_group_command, create_group_repeat_response)

    # Remove client from group
    command_check(sock, remove_client_from_group_command, remove_client_from_group_response)

    # Add client back to group
    command_check(sock, add_client_to_group_command, add_client_to_group_response)

    # Delete group_two entirely
    command_check(sock, delete_group_command, delete_group_response)

    # Delete client and verify it is removed from group_one
    command_check(sock, delete_client_command, delete_client_response)
    command_check(sock, get_group_after_delete_client_command, get_group_after_delete_client_response)

    check_details(sock, 2, 1, 2, 13)

    rc = broker_terminate_rc

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
