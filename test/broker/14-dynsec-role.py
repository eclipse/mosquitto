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
    "rolename": "", "correlationData": "2" }]
}
create_client_response = {'responses': [{'command': 'createClient', 'correlationData': '2'}]}

create_client2_command = { "commands": [{
    "command": "createClient", "username": "user_two",
    "password": "password",
    "textname": "Name", "textdescription": "Description",
    "rolename": "", "correlationData": "3" }]
}
create_client2_response = {'responses': [{'command': 'createClient', 'correlationData': '3'}]}

create_group_command = { "commands": [{
            "command": "createGroup", "groupname": "group_one",
            "textname": "Name", "textdescription": "Description",
            "correlationData":"3"}]}
create_group_response = {'responses':[{"command":"createGroup","correlationData":"3"}]}

create_role_command = { "commands": [{'command': 'createRole', 'correlationData': '3',
    "rolename": "basic", "acls":[
    {"acltype":"publishClientSend", "topic": "out/#", "priority":3, "allow": True}], "textname":"name", "textdescription":"desc"
    }]}
create_role_response = {'responses': [{'command': 'createRole', 'correlationData': '3'}]}

create_role2_command = { "commands": [{'command': 'createRole', 'correlationData': '3',
    "rolename": "basic2", "acls":[
    {"acltype":"publishClientSend", "topic": "out/#", "priority":3, "allow": True}], "textname":"name", "textdescription":"desc"
    }]}
create_role2_response = {'responses': [{'command': 'createRole', 'correlationData': '3'}]}


add_role_to_client_command = {"commands": [{'command': 'addClientRole', "username": "user_one",
    "rolename": "basic"}]}
add_role_to_client_response = {'responses': [{'command': 'addClientRole'}]}

add_role_to_client2_command = {"commands": [{'command': 'addClientRole', "username": "user_one",
    "rolename": "basic2"}]}
add_role_to_client2_response = {'responses': [{'command': 'addClientRole'}]}

add_role_to_group_command = {"commands": [{'command': 'addGroupRole', "groupname": "group_one",
    "rolename": "basic"}]}
add_role_to_group_response = {'responses': [{'command': 'addGroupRole'}]}


list_roles_verbose_command1 = { "commands": [{
    "command": "listRoles", "verbose": True, "correlationData": "21"}]
}
list_roles_verbose_response1 = {'responses': [{'command': 'listRoles', 'data':
    {'totalCount':3, 'roles': [
    {"rolename":"admin","acls":[
    {"acltype": "publishClientSend", "topic": "$CONTROL/dynamic-security/#", "priority":0, "allow": True },
    {"acltype": "publishClientReceive", "topic": "$CONTROL/dynamic-security/#", "priority":0, "allow": True },
    {"acltype": "publishClientReceive", "topic": "$SYS/#", "priority":0, "allow": True },
    {"acltype": "publishClientReceive", "topic": "#", "priority":0, "allow": True },
    {"acltype": "subscribePattern", "topic": "$CONTROL/dynamic-security/#", "priority":0, "allow": True },
    {"acltype": "subscribePattern", "topic": "$SYS/#", "priority":0, "allow": True },
    {"acltype": "subscribePattern", "topic": "#", "priority":0, "allow": True},
    {"acltype": "unsubscribePattern", "topic": "#", "priority":0, "allow": True}]},
    {'rolename': 'basic', "textname": "name", "textdescription": "desc",
    'acls': [{'acltype':'publishClientSend', 'topic': 'out/#', 'priority': 3, 'allow': True}]},
    {'rolename': 'basic2', "textname": "name", "textdescription": "desc",
    'acls': [{'acltype':'publishClientSend', 'topic': 'out/#', 'priority': 3, 'allow': True}]
    }]}, 'correlationData': '21'}]}

add_acl_command = {"commands": [{'command': "addRoleACL", "rolename":"basic", "acltype":"subscribeLiteral",
    "topic":"basic/out", "priority":1, "allow":True}]}
add_acl_response = {'responses': [{'command': 'addRoleACL'}]}

add_acl2_command = {"commands": [{'command': "addRoleACL", "rolename":"basic", "acltype":"subscribeLiteral",
    "topic":"basic/out", "priority":1, "allow":True}]}
add_acl2_response = {'responses': [{'command': 'addRoleACL', 'error':'ACL with this topic already exists'}]}

list_roles_verbose_command2 = { "commands": [{
    "command": "listRoles", "verbose": True, "correlationData": "22"}]
}
list_roles_verbose_response2 = {'responses': [{'command': 'listRoles', 'data': {'totalCount':3, 'roles':
    [{"rolename":"admin","acls":[
    {"acltype": "publishClientSend", "topic": "$CONTROL/dynamic-security/#", "priority":0, "allow": True },
    {"acltype": "publishClientReceive", "topic": "$CONTROL/dynamic-security/#", "priority":0, "allow": True },
    {"acltype": "publishClientReceive", "topic": "$SYS/#", "priority":0, "allow": True },
    {"acltype": "publishClientReceive", "topic": "#", "priority":0, "allow": True },
    {"acltype": "subscribePattern", "topic": "$CONTROL/dynamic-security/#", "priority":0, "allow": True },
    {"acltype": "subscribePattern", "topic": "$SYS/#", "priority":0, "allow": True },
    {"acltype": "subscribePattern", "topic": "#", "priority":0, "allow": True},
    {"acltype": "unsubscribePattern", "topic": "#", "priority":0, "allow": True}]},
    {'rolename': 'basic', 'textname': 'name', 'textdescription': 'desc', 'acls':
    [{'acltype':'publishClientSend', 'topic': 'out/#', 'priority': 3, 'allow': True},
    {'acltype':'subscribeLiteral', 'topic': 'basic/out', 'priority': 1, 'allow': True}]},
    {'rolename': 'basic2', "textname": "name", "textdescription": "desc",
    'acls': [{'acltype':'publishClientSend', 'topic': 'out/#', 'priority': 3, 'allow': True}]
    }]}, 'correlationData': '22'}]}

get_role_command = {"commands": [{'command': "getRole", "rolename":"basic"}]}
get_role_response = {'responses': [{'command': 'getRole', 'data': {'role':
    {'rolename': 'basic', 'textname': 'name', 'textdescription': 'desc', 'acls':
    [{'acltype':'publishClientSend', 'topic': 'out/#', 'priority': 3, 'allow': True},
    {'acltype':'subscribeLiteral', 'topic': 'basic/out', 'priority': 1, 'allow': True}],
    }}}]}

remove_acl_command = {"commands": [{'command': "removeRoleACL", "rolename":"basic", "acltype":"subscribeLiteral",
    "topic":"basic/out"}]}
remove_acl_response = {'responses': [{'command': 'removeRoleACL'}]}

remove_acl2_command = {"commands": [{'command': "removeRoleACL", "rolename":"basic", "acltype":"subscribeLiteral",
    "topic":"basic/out"}]}
remove_acl2_response = {'responses': [{'command': 'removeRoleACL', 'error':'ACL not found'}]}

delete_role_command = {"commands": [{'command': "deleteRole", "rolename":"basic"}]}
delete_role_response = {"responses": [{"command": "deleteRole"}]}

delete_role2_command = {"commands": [{'command': "deleteRole", "rolename":"basic"}]}
delete_role2_response = {"responses": [{"command": "deleteRole"}]}

list_clients_verbose_command = { "commands": [{
    "command": "listClients", "verbose": True, "correlationData": "20"}]
}
list_clients_verbose_response = {'responses':[{"command": "listClients", "data":{'totalCount':3, "clients":[
    {'username': 'admin', 'textname': 'Dynsec admin user', 'roles': [{'rolename': 'admin'}], 'groups': []},
    {"username":"user_one", "clientid":"cid", "textname":"Name", "textdescription":"Description",
    "groups":[], "roles":[{'rolename':'basic'}, {'rolename':'basic2'}]},
    {"username":"user_two", "textname":"Name", "textdescription":"Description",
    "groups":[], "roles":[]}]}, "correlationData":"20"}]}

list_groups_verbose_command = { "commands": [{
    "command": "listGroups", "verbose": True, "correlationData": "20"}]
}
list_groups_verbose_response = {'responses':[{"command": "listGroups", "data":{'totalCount':1, "groups":[
    {"groupname":"group_one", "textname":"Name", "textdescription":"Description",
    "clients":[], "roles":[{'rolename':'basic'}]}]}, "correlationData":"20"}]}

remove_role_from_client_command = {"commands": [{'command': 'removeClientRole', "username": "user_one",
    "rolename": "basic"}]}
remove_role_from_client_response = {'responses': [{'command': 'removeClientRole'}]}

remove_role_from_group_command = {"commands": [{'command': 'removeGroupRole', "groupname": "group_one",
    "rolename": "basic"}]}
remove_role_from_group_response = {'responses': [{'command': 'removeGroupRole'}]}


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
    command_check(sock, create_client2_command, create_client2_response)
    command_check(sock, create_client_command, create_client_response)

    # Create group
    command_check(sock, create_group_command, create_group_response)

    # Create role
    command_check(sock, create_role_command, create_role_response)
    command_check(sock, create_role2_command, create_role2_response)

    # Add role to client
    command_check(sock, add_role_to_client2_command, add_role_to_client2_response)
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
    command_check(sock, add_acl2_command, add_acl2_response)

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
    command_check(sock, remove_acl2_command, remove_acl2_response)

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
