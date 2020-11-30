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
    {"username":"user_one"}, {"username":"user_two"}], "roles":[]},
    {'groupname': 'group_two', 'textname': 'Name', 'textdescription': 'description', 'clients': [
    {"username":"user_one"}], "roles":[]}
    ]},
    'correlationData': '15'}]}

list_clients_verbose_command = { "commands": [{
            "command": "listClients", "verbose": True, "correlationData": "20"}]}
list_clients_verbose_response = {'responses':[{"command": "listClients", "data":{"totalCount":3, "clients":[
            {'username': 'admin', 'textname': 'Dynsec admin user', 'roles': [{'rolename': 'admin'}], 'groups': []},
            {"username":"user_one", "clientid":"cid", "textname":"Name", "textdescription":"description",
            "groups":[{"groupname":"group_one"}, {"groupname":"group_two"}], "roles":[]},
            {"username":"user_two", "textname":"Name", "textdescription":"description",
            "groups":[{"groupname":"group_one"}], "roles":[]},
            ]}, "correlationData":"20"}]}

get_group_command = { "commands": [{"command": "getGroup", "groupname":"group_one"}]}
get_group_response = {'responses':[{'command': 'getGroup', 'data': {'group': {'groupname': 'group_one',
    'textname':'Name', 'textdescription':'description', 'clients': [{"username":"user_one"}, {"username":"user_two"}], 'roles': []}}}]}

add_client_to_group_command = {"commands": [{"command":"addGroupClient", "username":"user_one",
            "groupname": "group_one", "correlationData":"1234"}]}
add_client_to_group_response = {'responses':[{'command': 'addGroupClient', 'correlationData': '1234'}]}
add_duplicate_client_to_group_response = {'responses':[{'command': 'addGroupClient', 'correlationData': '1234'}]}

add_client_to_group2_command = {"commands": [{"command":"addGroupClient", "username":"user_one",
            "groupname": "group_two", "correlationData":"1234"}]}
add_client_to_group2_response = {'responses':[{'command': 'addGroupClient', 'correlationData': '1234'}]}

add_client2_to_group_command = {"commands": [{"command":"addGroupClient", "username":"user_two",
            "groupname": "group_one", "correlationData":"1235"}]}
add_client2_to_group_response = {'responses':[{'command': 'addGroupClient', 'correlationData': '1235'}]}

remove_client_from_group_command = {"commands": [{"command":"removeGroupClient", "username":"user_one",
            "groupname": "group_one", "correlationData":"4321"}]}
remove_client_from_group_response = {'responses':[{'command': 'removeGroupClient', 'correlationData': '4321'}]}

delete_group_command = {"commands": [{"command":"deleteGroup", "groupname":"group_one", "correlationData":"5678"}]}
delete_group_response = {'responses':[{"command":"deleteGroup", "correlationData":"5678"}]}


rc = 1
keepalive = 10
connect_packet = mosq_test.gen_connect("ctrl-test", keepalive=keepalive, username="admin", password="admin")
connack_packet = mosq_test.gen_connack(rc=0)

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

    # Get group
    command_check(sock, get_group_command, get_group_response)

    # List groups non-verbose
    command_check(sock, list_groups_command, list_groups_response)

    # List groups verbose
    command_check(sock, list_groups_verbose_command, list_groups_verbose_response, "list groups")

    # List clients verbose
    command_check(sock, list_clients_verbose_command, list_clients_verbose_response)

    # Kill broker and restart, checking whether our changes were saved.
    broker.terminate()
    broker.wait()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    # Add duplicate group
    command_check(sock, create_group_command, create_group_repeat_response)

    # Remove client from group
    command_check(sock, remove_client_from_group_command, remove_client_from_group_response)

    # Add client back to group
    command_check(sock, add_client_to_group_command, add_client_to_group_response)

    # Delete group entirely
    command_check(sock, delete_group_command, delete_group_response)

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
