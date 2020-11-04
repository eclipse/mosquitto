#!/usr/bin/env python3

from mosq_test_helper import *
import json

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
            "textName": "Name", "textDescription": "Description",
            "roleName": "", "correlationData": "2" }]}
create_client_response = {'responses':[{"command":"createClient","correlationData":"2"}]}

create_group_command = { "commands": [{
            "command": "createGroup", "groupName": "group_one",
            "textName": "Name", "textDescription": "Description",
            "correlationData":"3"}]}
create_group_response = {'responses':[{"command":"createGroup","correlationData":"3"}]}
create_group_repeat_response = {'responses':[{"command":"createGroup","error":"Group already exists","correlationData":"3"}]}

list_groups_command = { "commands": [{
            "command": "listGroups", "verbose": False, "correlationData": "10"}]}
list_groups_response = {'responses':[{"command": "listGroups", "data":{"totalCount":1, "groups":["group_one"]},"correlationData":"10"}]}

list_groups_verbose_command = { "commands": [{
            "command": "listGroups", "verbose": True, "correlationData": "15"}]}
list_groups_verbose_response = {'responses':[{'command': 'listGroups', 'data': {"totalCount":1, 'groups':
            [{'groupName': 'group_one', 'textName': 'Name', 'textDescription': 'Description', 'clients': [
                {"username":"user_one"}], "roles":[]}]},
            'correlationData': '15'}]}

list_clients_verbose_command = { "commands": [{
            "command": "listClients", "verbose": True, "correlationData": "20"}]}
list_clients_verbose_response = {'responses':[{"command": "listClients", "data":{"totalCount":1, "clients":[
            {"username":"user_one", "clientid":"cid", "textName":"Name", "textDescription":"Description",
            "groups":[{"groupName":"group_one"}], "roles":[]}]}, "correlationData":"20"}]}

get_group_command = { "commands": [{"command": "getGroup", "groupName":"group_one"}]}
get_group_response = {'responses':[{'command': 'getGroup', 'data': {'group': {'groupName': 'group_one',
            'textName':'Name', 'textDescription':'Description', 'clients': [{"username":"user_one"}], 'roles': []}}}]}

add_client_to_group_command = {"commands": [{"command":"addGroupClient", "username":"user_one",
            "groupName": "group_one", "correlationData":"1234"}]}
add_client_to_group_response = {'responses':[{'command': 'addGroupClient', 'correlationData': '1234'}]}

remove_client_from_group_command = {"commands": [{"command":"removeGroupClient", "username":"user_one",
            "groupName": "group_one", "correlationData":"4321"}]}
remove_client_from_group_response = {'responses':[{'command': 'removeGroupClient', 'correlationData': '4321'}]}

delete_group_command = {"commands": [{"command":"deleteGroup", "groupName":"group_one", "correlationData":"5678"}]}
delete_group_response = {'responses':[{"command":"deleteGroup", "correlationData":"5678"}]}


rc = 1
keepalive = 10
connect_packet = mosq_test.gen_connect("ctrl-test", keepalive=keepalive)
connack_packet = mosq_test.gen_connack(rc=0)

mid = 2
subscribe_packet = mosq_test.gen_subscribe(mid, "$CONTROL/#", 1)
suback_packet = mosq_test.gen_suback(mid, 1)

try:
    os.mkdir(str(port))
    with open("%d/dynamic-security.json" % port, 'w') as f:
        f.write('{"defaultACLAction": {"publishClientSend":"allow", "publishClientReceive":"allow", "subscribe":"allow", "unsubscribe":"allow"}}')
except FileExistsError:
    try:
        os.remove(f"{port}/dynamic-security.json")
    except FileNotFoundError:
        pass

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    # Add client
    command_check(sock, create_client_command, create_client_response)

    # Add group
    command_check(sock, create_group_command, create_group_response)

    # Add client to group
    command_check(sock, add_client_to_group_command, add_client_to_group_response)

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
