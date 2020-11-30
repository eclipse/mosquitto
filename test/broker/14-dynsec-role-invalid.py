#!/usr/bin/env python3

# Check invalid inputs for role commands

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
        print(expected_response)
        print(response)
        if msg != "":
            print(msg)
        raise ValueError(response)



port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

# Create client for modifying
create_client0_command = { 'commands': [{'command': 'createClient', 'username':'validclient' }] }
create_client0_response = {'responses': [{'command': 'createClient'}]}

# Create group for modifying
create_group0_command = { 'commands': [{'command': 'createGroup', 'groupname':'validgroup' }] }
create_group0_response = {'responses': [{'command': 'createGroup'}]}

# Create role for modifying
create_role0_command = { 'commands': [{'command': 'createRole', 'rolename':'validrole' }] }
create_role0_response = {'responses': [{'command': 'createRole'}]}

# Add ACL for modifying
add_role_acl0_command = { 'commands': [{'command': 'addRoleACL', 'rolename':'validrole', 'acltype':'unsubscribePattern', 'topic':'validtopic', 'allow':True }] }
add_role_acl0_response = {'responses': [{'command': 'addRoleACL'}]}

# ==========================================================================
# Create role
# ==========================================================================

# No rolename
create_role1_command = { 'commands': [{'command': 'createRole' }] }
create_role1_response = {'responses': [{'command': 'createRole', 'error': 'Invalid/missing rolename'}]}

# Rolename not a string
create_role2_command = { 'commands': [{'command': 'createRole', 'rolename':5 }] }
create_role2_response = {'responses': [{'command': 'createRole', 'error': 'Invalid/missing rolename'}]}

# Rolename not UTF-8
create_role3_command = { 'commands': [{'command': 'createRole', 'rolename': '￿LO' }] }
create_role3_response = {'responses': [{'command': 'createRole', 'error': 'Role name not valid UTF-8'}]}

# textname not a string
create_role4_command = { 'commands': [{'command': 'createRole', 'rolename':'g', 'textname':5 }] }
create_role4_response = {'responses': [{'command': 'createRole', 'error': 'Invalid/missing textname'}]}

# textdescription not a string
create_role5_command = { 'commands': [{'command': 'createRole', 'rolename':'g', 'textdescription':5 }] }
create_role5_response = {'responses': [{'command': 'createRole', 'error': 'Invalid/missing textdescription'}]}

# Role already exists
create_role6_command = { 'commands': [{'command': 'createRole', 'rolename': 'validrole'}]}
create_role6_response = {'responses': [{'command': 'createRole', 'error': 'Role already exists'}]}

# Bad ACLs
#create_role7_command = { 'commands': [{'command': 'createRole', 'rolename': 'role', 'roles':[{'rolename':'notfound'}]}] }
#create_role7_response = {'responses': [{'command': 'createRole', 'error': 'Role not found'}]}

# ==========================================================================
# Delete role
# ==========================================================================

# No rolename
delete_role1_command = { 'commands': [{'command': 'deleteRole' }] }
delete_role1_response = {'responses': [{'command': 'deleteRole', 'error': 'Invalid/missing rolename'}]}

# Rolename not a string
delete_role2_command = { 'commands': [{'command': 'deleteRole', 'rolename':5 }] }
delete_role2_response = {'responses': [{'command': 'deleteRole', 'error': 'Invalid/missing rolename'}]}

# Rolename not UTF-8
delete_role3_command = { 'commands': [{'command': 'deleteRole', 'rolename': '￿LO' }] }
delete_role3_response = {'responses': [{'command': 'deleteRole', 'error': 'Role name not valid UTF-8'}]}

# Role not found
delete_role4_command = { 'commands': [{'command': 'deleteRole', 'rolename': 'role'}]}
delete_role4_response = {'responses': [{'command': 'deleteRole', 'error': 'Role not found'}]}

# ==========================================================================
# Get role
# ==========================================================================

# No rolename
get_role1_command = { 'commands': [{'command': 'getRole'}] }
get_role1_response = {'responses': [{'command': 'getRole', 'error': 'Invalid/missing rolename'}]}

# rolename not a string
get_role2_command = { 'commands': [{'command': 'getRole', 'rolename':5}] }
get_role2_response = {'responses': [{'command': 'getRole', 'error': 'Invalid/missing rolename'}]}

# rolename not UTF-8
get_role3_command = { 'commands': [{'command': 'getRole', 'rolename': '￿LO' }] }
get_role3_response = {'responses': [{'command': 'getRole', 'error': 'Role name not valid UTF-8'}]}

# role not found
get_role4_command = { 'commands': [{'command': 'getRole', 'rolename':"notfound"}] }
get_role4_response = {'responses': [{'command': 'getRole', 'error': 'Role not found'}]}


# ==========================================================================
# Add role ACL
# ==========================================================================

add_role_acl1_command = { 'commands': [{'command': 'addRoleACL'}]}
add_role_acl1_response = {'responses': [{'command': 'addRoleACL', 'error': 'Invalid/missing rolename'}]}

add_role_acl2_command = { 'commands': [{'command': 'addRoleACL', 'rolename':5}]}
add_role_acl2_response = {'responses': [{'command': 'addRoleACL', 'error': 'Invalid/missing rolename'}]}

add_role_acl3_command = { 'commands': [{'command': 'addRoleACL', 'rolename': '￿LO' }] }
add_role_acl3_response = {'responses': [{'command': 'addRoleACL', 'error': 'Role name not valid UTF-8'}]}

add_role_acl4_command = { 'commands': [{'command': 'addRoleACL', 'rolename': 'notvalid' }] }
add_role_acl4_response = {'responses': [{'command': 'addRoleACL', 'error': 'Role not found'}]}

add_role_acl5_command = { 'commands': [{'command': 'addRoleACL', 'rolename': 'validrole' }] }
add_role_acl5_response = {'responses': [{'command': 'addRoleACL', 'error': 'Invalid/missing acltype'}]}

add_role_acl6_command = { 'commands': [{'command': 'addRoleACL', 'rolename': 'validrole', 'acltype':'notvalid' }] }
add_role_acl6_response = {'responses': [{'command': 'addRoleACL', 'error': 'Unknown acltype'}]}

add_role_acl7_command = { 'commands': [{'command': 'addRoleACL', 'rolename': 'validrole', 'acltype':'unsubscribePattern' }] }
add_role_acl7_response = {'responses': [{'command': 'addRoleACL', 'error': 'Invalid/missing topic'}]}

add_role_acl8_command = { 'commands': [{'command': 'addRoleACL', 'rolename': 'validrole', 'acltype':'subscribePattern', 'topic':5 }] }
add_role_acl8_response = {'responses': [{'command': 'addRoleACL', 'error': 'Invalid/missing topic'}]}

add_role_acl9_command = { 'commands': [{'command': 'addRoleACL', 'rolename': 'validrole', 'acltype':'unsubscribeLiteral', 'topic':'￿LO' }] }
add_role_acl9_response = {'responses': [{'command': 'addRoleACL', 'error': 'Topic not valid UTF-8'}]}

add_role_acl10_command = { 'commands': [{'command': 'addRoleACL', 'rolename': 'validrole', 'acltype':'unsubscribeLiteral', 'topic':'not/#/valid' }] }
add_role_acl10_response = {'responses': [{'command': 'addRoleACL', 'error': 'Invalid ACL topic'}]}


# ==========================================================================
# Remove role ACL
# ==========================================================================

remove_role_acl1_command = { 'commands': [{'command': 'removeRoleACL'}]}
remove_role_acl1_response = {'responses': [{'command': 'removeRoleACL', 'error': 'Invalid/missing rolename'}]}

remove_role_acl2_command = { 'commands': [{'command': 'removeRoleACL', 'rolename':5}]}
remove_role_acl2_response = {'responses': [{'command': 'removeRoleACL', 'error': 'Invalid/missing rolename'}]}

remove_role_acl3_command = { 'commands': [{'command': 'removeRoleACL', 'rolename': '￿LO' }] }
remove_role_acl3_response = {'responses': [{'command': 'removeRoleACL', 'error': 'Role name not valid UTF-8'}]}

remove_role_acl4_command = { 'commands': [{'command': 'removeRoleACL', 'rolename': 'notvalid' }] }
remove_role_acl4_response = {'responses': [{'command': 'removeRoleACL', 'error': 'Role not found'}]}

remove_role_acl5_command = { 'commands': [{'command': 'removeRoleACL', 'rolename': 'validrole' }] }
remove_role_acl5_response = {'responses': [{'command': 'removeRoleACL', 'error': 'Invalid/missing acltype'}]}

remove_role_acl6_command = { 'commands': [{'command': 'removeRoleACL', 'rolename': 'validrole', 'acltype':'notvalid' }] }
remove_role_acl6_response = {'responses': [{'command': 'removeRoleACL', 'error': 'Unknown acltype'}]}

remove_role_acl7_command = { 'commands': [{'command': 'removeRoleACL', 'rolename': 'validrole', 'acltype':'unsubscribePattern' }] }
remove_role_acl7_response = {'responses': [{'command': 'removeRoleACL', 'error': 'Invalid/missing topic'}]}

remove_role_acl8_command = { 'commands': [{'command': 'removeRoleACL', 'rolename': 'validrole', 'acltype':'unsubscribePattern', 'topic':5 }] }
remove_role_acl8_response = {'responses': [{'command': 'removeRoleACL', 'error': 'Invalid/missing topic'}]}

remove_role_acl9_command = { 'commands': [{'command': 'removeRoleACL', 'rolename': 'validrole', 'acltype':'unsubscribePattern', 'topic':'￿LO' }] }
remove_role_acl9_response = {'responses': [{'command': 'removeRoleACL', 'error': 'Topic not valid UTF-8'}]}


# ==========================================================================
# Modify role
# ==========================================================================

# No groupname
modify_group1_command = { 'commands': [{'command': 'modifyRole'}]}
modify_group1_response = {'responses': [{'command': 'modifyRole', 'error': 'Invalid/missing groupname'}]}

# Username not a string
modify_group2_command = { 'commands': [{'command': 'modifyRole', 'groupname':5}]}
modify_group2_response = {'responses': [{'command': 'modifyRole', 'error': 'Invalid/missing groupname'}]}

# Username not UTF-8
modify_group3_command = { 'commands': [{'command': 'modifyRole', 'rolename': '￿LO' }] }
modify_group3_response = {'responses': [{'command': 'modifyRole', 'error': 'Role name not valid UTF-8'}]}

# roles not a list
modify_group4_command = { 'commands': [{'command': 'modifyRole', 'groupname':'validgroup', 'password':'test', 'roles':'string'}]}
modify_group4_response = {'responses': [{'command': 'modifyRole', 'error': "'roles' not an array or missing/invalid rolename"}]}

# No rolename
modify_group5_command = { 'commands': [{'command': 'modifyRole', 'groupname':'validgroup', 'roles':[{}]}]}
modify_group5_response = {'responses': [{'command': 'modifyRole', 'error': "'roles' not an array or missing/invalid rolename"}]}

# rolename not a string
modify_group6_command = { 'commands': [{'command': 'modifyRole', 'groupname':'validgroup', 'roles':[{'rolename':5}]}]}
modify_group6_response = {'responses': [{'command': 'modifyRole', 'error': "'roles' not an array or missing/invalid rolename"}]}

# rolename not UTF-8
modify_group3_command = { 'commands': [{'command': 'modifyRole', 'rolename': '￿LO' }] }
#modify_group7_command = { 'commands': [{'command': 'modifyRole', 'groupname':'validgroup'}]}
#modify_group7_response = {'responses': [{'command': 'modifyRole', 'error': 'Invalid/missing rolename'}]}

# Role not found
modify_group8_command = { 'commands': [{'command': 'modifyRole', 'groupname':'notfound', 'rolename':'notfound'}]}
modify_group8_response = {'responses': [{'command': 'modifyRole', 'error': 'Role not found'}]}

# Role not found
modify_group9_command = { 'commands': [{'command': 'modifyRole', 'groupname':'validgroup', 'roles':[{'rolename':'notfound'}]}]}
modify_group9_response = {'responses': [{'command': 'modifyRole', 'error': 'Role not found'}]}


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

    command_check(sock, create_client0_command, create_client0_response, "0")
    command_check(sock, create_group0_command, create_group0_response, "0")
    command_check(sock, create_role0_command, create_role0_response, "0")
    command_check(sock, add_role_acl0_command, add_role_acl0_response, "0")

    command_check(sock, create_role1_command, create_role1_response, "1")
    command_check(sock, create_role2_command, create_role2_response, "2")
    command_check(sock, create_role3_command, create_role3_response, "3")
    command_check(sock, create_role4_command, create_role4_response, "4")
    command_check(sock, create_role5_command, create_role5_response, "5")
    command_check(sock, create_role6_command, create_role6_response, "6")
    #command_check(sock, create_role7_command, create_role7_response, "7")

    command_check(sock, delete_role1_command, delete_role1_response, "1")
    command_check(sock, delete_role2_command, delete_role2_response, "2")
    command_check(sock, delete_role3_command, delete_role3_response, "3")
    command_check(sock, delete_role4_command, delete_role4_response, "4")

    command_check(sock, get_role1_command, get_role1_response, "1")
    command_check(sock, get_role2_command, get_role2_response, "2")
    command_check(sock, get_role3_command, get_role3_response, "3")
    command_check(sock, get_role4_command, get_role4_response, "4")

    command_check(sock, add_role_acl1_command, add_role_acl1_response, "1")
    command_check(sock, add_role_acl2_command, add_role_acl2_response, "2")
    command_check(sock, add_role_acl3_command, add_role_acl3_response, "3")
    command_check(sock, add_role_acl4_command, add_role_acl4_response, "4")
    command_check(sock, add_role_acl5_command, add_role_acl5_response, "5")
    command_check(sock, add_role_acl6_command, add_role_acl6_response, "6")
    command_check(sock, add_role_acl7_command, add_role_acl7_response, "7")
    command_check(sock, add_role_acl8_command, add_role_acl8_response, "8")
    command_check(sock, add_role_acl9_command, add_role_acl9_response, "9")
    command_check(sock, add_role_acl10_command, add_role_acl10_response, "10")

    command_check(sock, remove_role_acl1_command, remove_role_acl1_response, "1")
    command_check(sock, remove_role_acl2_command, remove_role_acl2_response, "2")
    command_check(sock, remove_role_acl3_command, remove_role_acl3_response, "3")
    command_check(sock, remove_role_acl4_command, remove_role_acl4_response, "4")
    command_check(sock, remove_role_acl5_command, remove_role_acl5_response, "5")
    command_check(sock, remove_role_acl6_command, remove_role_acl6_response, "6")
    command_check(sock, remove_role_acl7_command, remove_role_acl7_response, "7")
    command_check(sock, remove_role_acl8_command, remove_role_acl8_response, "8")
    command_check(sock, remove_role_acl9_command, remove_role_acl9_response, "9")

    #command_check(sock, modify_role1_command, modify_role1_response, "1")
    #command_check(sock, modify_role2_command, modify_role2_response, "2")
    ##command_check(sock, modify_role3_command, modify_role3_response, "3")
    #command_check(sock, modify_role4_command, modify_role4_response, "4")
    #command_check(sock, modify_role5_command, modify_role5_response, "5")
    #command_check(sock, modify_role6_command, modify_role6_response, "6")
    ##command_check(sock, modify_role7_command, modify_role7_response, "7")
    #command_check(sock, modify_role8_command, modify_role8_response, "8")
    #command_check(sock, modify_role9_command, modify_role9_response, "9")

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
