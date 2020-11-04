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
    "roleName": "", "correlationData": "2" }]
}
create_client_response = {'responses': [{'command': 'createClient', 'correlationData': '2'}]}

create_group_command = { "commands": [{
            "command": "createGroup", "groupName": "group_one",
            "textName": "Name", "textDescription": "Description",
            "correlationData":"3"}]}
create_group_response = {'responses':[{"command":"createGroup","correlationData":"3"}]}

create_role_command = { "commands": [{'command': 'createRole', 'correlationData': '3',
    "roleName": "basic", "acls":[
    {"aclType":"publishClientSend", "topic": "out/#", "priority":3, "allow": True}], "textName":"name", "textDescription":"desc"
    }]}
create_role_response = {'responses': [{'command': 'createRole', 'correlationData': '3'}]}


add_role_to_client_command = {"commands": [{'command': 'addClientRole', "username": "user_one",
    "roleName": "basic"}]}
add_role_to_client_response = {'responses': [{'command': 'addClientRole'}]}

add_role_to_group_command = {"commands": [{'command': 'addGroupRole', "groupName": "group_one",
    "roleName": "basic"}]}
add_role_to_group_response = {'responses': [{'command': 'addGroupRole'}]}


list_roles_verbose_command1 = { "commands": [{
    "command": "listRoles", "verbose": True, "correlationData": "21"}]
}
list_roles_verbose_response1 = {'responses': [{'command': 'listRoles', 'data':
    {'totalCount':1, 'roles': [{'roleName': 'basic', "textName": "name", "textDescription": "desc",
    'acls': [{'aclType':'publishClientSend', 'topic': 'out/#', 'priority': 3, 'allow': True}]
    }]}, 'correlationData': '21'}]}

add_acl_command = {"commands": [{'command': "addRoleACL", "roleName":"basic", "aclType":"subscribeLiteral",
    "topic":"basic/out", "priority":1, "allow":True}]}
add_acl_response = {'responses': [{'command': 'addRoleACL'}]}

list_roles_verbose_command2 = { "commands": [{
    "command": "listRoles", "verbose": True, "correlationData": "22"}]
}
list_roles_verbose_response2 = {'responses': [{'command': 'listRoles', 'data': {'totalCount':1, 'roles':
    [{'roleName': 'basic', 'textName': 'name', 'textDescription': 'desc', 'acls':
    [{'aclType':'publishClientSend', 'topic': 'out/#', 'priority': 3, 'allow': True},
    {'aclType':'subscribeLiteral', 'topic': 'basic/out', 'priority': 1, 'allow': True}],
    }]}, 'correlationData': '22'}]}

get_role_command = {"commands": [{'command': "getRole", "roleName":"basic"}]}
get_role_response = {'responses': [{'command': 'getRole', 'data': {'role':
    {'roleName': 'basic', 'textName': 'name', 'textDescription': 'desc', 'acls':
    [{'aclType':'publishClientSend', 'topic': 'out/#', 'priority': 3, 'allow': True},
    {'aclType':'subscribeLiteral', 'topic': 'basic/out', 'priority': 1, 'allow': True}],
    }}}]}

remove_acl_command = {"commands": [{'command': "removeRoleACL", "roleName":"basic", "aclType":"subscribeLiteral",
    "topic":"basic/out"}]}
remove_acl_response = {'responses': [{'command': 'removeRoleACL'}]}

delete_role_command = {"commands": [{'command': "deleteRole", "roleName":"basic"}]}
delete_role_response = {"responses": [{"command": "deleteRole"}]}

list_clients_verbose_command = { "commands": [{
    "command": "listClients", "verbose": True, "correlationData": "20"}]
}
list_clients_verbose_response = {'responses':[{"command": "listClients", "data":{'totalCount':1, "clients":[
    {"username":"user_one", "clientid":"cid", "textName":"Name", "textDescription":"Description",
    "groups":[], "roles":[{'roleName':'basic'}]}]}, "correlationData":"20"}]}

list_groups_verbose_command = { "commands": [{
    "command": "listGroups", "verbose": True, "correlationData": "20"}]
}
list_groups_verbose_response = {'responses':[{"command": "listGroups", "data":{'totalCount':1, "groups":[
    {"groupName":"group_one", "textName":"Name", "textDescription":"Description",
    "clients":[], "roles":[{'roleName':'basic'}]}]}, "correlationData":"20"}]}

remove_role_from_client_command = {"commands": [{'command': 'removeClientRole', "username": "user_one",
    "roleName": "basic"}]}
remove_role_from_client_response = {'responses': [{'command': 'removeClientRole'}]}

remove_role_from_group_command = {"commands": [{'command': 'removeGroupRole', "groupName": "group_one",
    "roleName": "basic"}]}
remove_role_from_group_response = {'responses': [{'command': 'removeGroupRole'}]}


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

    # Create client
    command_check(sock, create_client_command, create_client_response)

    # Create group
    command_check(sock, create_group_command, create_group_response)

    # Create role
    command_check(sock, create_role_command, create_role_response)

    # Add role to client
    command_check(sock, add_role_to_client_command, add_role_to_client_response)

    # Add role to group
    command_check(sock, add_role_to_group_command, add_role_to_group_response)

    # List clients verbose
    command_check(sock, list_clients_verbose_command, list_clients_verbose_response)

    # List groups verbose
    command_check(sock, list_groups_verbose_command, list_groups_verbose_response)

    # List roles verbose 1
    command_check(sock, list_roles_verbose_command1, list_roles_verbose_response1, "list roles verbose 1a")

    # Add ACL
    command_check(sock, add_acl_command, add_acl_response)

    # List roles verbose 2
    command_check(sock, list_roles_verbose_command2, list_roles_verbose_response2, "list roles verbose 2a")

    # Kill broker and restart, checking whether our changes were saved.
    broker.terminate()
    broker.wait()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    # List roles verbose 2
    command_check(sock, list_roles_verbose_command2, list_roles_verbose_response2, "list roles verbose 2b")

    # Get role
    command_check(sock, get_role_command, get_role_response)

    # Remove ACL
    command_check(sock, remove_acl_command, remove_acl_response)

    # List roles verbose 1
    command_check(sock, list_roles_verbose_command1, list_roles_verbose_response1, "list roles verbose 1b")

    # Remove role from client
    command_check(sock, remove_role_from_client_command, remove_role_from_client_response)

    # Remove role from group
    command_check(sock, remove_role_from_group_command, remove_role_from_group_response)

    # Delete role
    command_check(sock, delete_role_command, delete_role_response)

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
