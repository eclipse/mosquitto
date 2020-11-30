#!/usr/bin/env python3

# Check invalid inputs for group commands

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

# ==========================================================================
# Create group
# ==========================================================================

# No groupname
create_group1_command = { 'commands': [{'command': 'createGroup' }] }
create_group1_response = {'responses': [{'command': 'createGroup', 'error': 'Invalid/missing groupname'}]}

# Groupname not a string
create_group2_command = { 'commands': [{'command': 'createGroup', 'groupname':5 }] }
create_group2_response = {'responses': [{'command': 'createGroup', 'error': 'Invalid/missing groupname'}]}

# Groupname not UTF-8
create_group3_command = { 'commands': [{'command': 'createGroup', 'groupname': '￿LO' }] }
create_group3_response = {'responses': [{'command': 'createGroup', 'error': 'Group name not valid UTF-8'}]}

# textname not a string
create_group4_command = { 'commands': [{'command': 'createGroup', 'groupname':'g', 'textname':5 }] }
create_group4_response = {'responses': [{'command': 'createGroup', 'error': 'Invalid/missing textname'}]}

# textdescription not a string
create_group5_command = { 'commands': [{'command': 'createGroup', 'groupname':'g', 'textdescription':5 }] }
create_group5_response = {'responses': [{'command': 'createGroup', 'error': 'Invalid/missing textdescription'}]}

# Group already exists
create_group6_command = { 'commands': [{'command': 'createGroup', 'groupname': 'validgroup'}]}
create_group6_response = {'responses': [{'command': 'createGroup', 'error': 'Group already exists'}]}

# Role not found
create_group7_command = { 'commands': [{'command': 'createGroup', 'groupname': 'group', 'roles':[{'rolename':'notfound'}]}] }
create_group7_response = {'responses': [{'command': 'createGroup', 'error': 'Role not found'}]}

# ==========================================================================
# Delete group
# ==========================================================================

# No groupname
delete_group1_command = { 'commands': [{'command': 'deleteGroup' }] }
delete_group1_response = {'responses': [{'command': 'deleteGroup', 'error': 'Invalid/missing groupname'}]}

# Groupname not a string
delete_group2_command = { 'commands': [{'command': 'deleteGroup', 'groupname':5 }] }
delete_group2_response = {'responses': [{'command': 'deleteGroup', 'error': 'Invalid/missing groupname'}]}

# Groupname not UTF-8
delete_group3_command = { 'commands': [{'command': 'deleteGroup', 'groupname': '￿LO' }] }
delete_group3_response = {'responses': [{'command': 'deleteGroup', 'error': 'Group name not valid UTF-8'}]}

# Group not found
delete_group4_command = { 'commands': [{'command': 'deleteGroup', 'groupname': 'group'}]}
delete_group4_response = {'responses': [{'command': 'deleteGroup', 'error': 'Group not found'}]}

# ==========================================================================
# Add role
# ==========================================================================

# No groupname
add_role1_command = { 'commands': [{'command': 'addGroupRole' }] }
add_role1_response = {'responses': [{'command': 'addGroupRole', 'error': 'Invalid/missing groupname'}]}

# Groupname not a string
add_role2_command = { 'commands': [{'command': 'addGroupRole', 'groupname':5 }] }
add_role2_response = {'responses': [{'command': 'addGroupRole', 'error': 'Invalid/missing groupname'}]}

# Groupname not UTF-8
add_role3_command = { 'commands': [{'command': 'addGroupRole', 'groupname': '￿LO' }] }
add_role3_response = {'responses': [{'command': 'addGroupRole', 'error': 'Group name not valid UTF-8'}]}

# No rolename
add_role4_command = { 'commands': [{'command': 'addGroupRole', 'groupname':'g' }] }
add_role4_response = {'responses': [{'command': 'addGroupRole', 'error': 'Invalid/missing rolename'}]}

# Rolename not a string
add_role5_command = { 'commands': [{'command': 'addGroupRole', 'groupname':'g', 'rolename':5 }] }
add_role5_response = {'responses': [{'command': 'addGroupRole', 'error': 'Invalid/missing rolename'}]}

# Rolename not UTF-8
add_role6_command = { 'commands': [{'command': 'addGroupRole', 'groupname':'g', 'rolename':'￿LO' }] }
add_role6_response = {'responses': [{'command': 'addGroupRole', 'error': 'Role name not valid UTF-8'}]}

# Group not found
add_role7_command = { 'commands': [{'command': 'addGroupRole', 'groupname':'notfound', 'rolename':'notfound' }] }
add_role7_response = {'responses': [{'command': 'addGroupRole', 'error': 'Group not found'}]}

# Role not found
add_role8_command = { 'commands': [{'command': 'addGroupRole', 'groupname':'validgroup', 'rolename':'notfound' }] }
add_role8_response = {'responses': [{'command': 'addGroupRole', 'error': 'Role not found'}]}


# ==========================================================================
# Remove role
# ==========================================================================

# No groupname
remove_role1_command = { 'commands': [{'command': 'removeGroupRole' }] }
remove_role1_response = {'responses': [{'command': 'removeGroupRole', 'error': 'Invalid/missing groupname'}]}

# Groupname not a string
remove_role2_command = { 'commands': [{'command': 'removeGroupRole', 'groupname':5 }] }
remove_role2_response = {'responses': [{'command': 'removeGroupRole', 'error': 'Invalid/missing groupname'}]}

# Groupname not UTF-8
remove_role3_command = { 'commands': [{'command': 'removeGroupRole', 'groupname': '￿LO' }] }
remove_role3_response = {'responses': [{'command': 'removeGroupRole', 'error': 'Group name not valid UTF-8'}]}

# No rolename
remove_role4_command = { 'commands': [{'command': 'removeGroupRole', 'groupname':'g' }] }
remove_role4_response = {'responses': [{'command': 'removeGroupRole', 'error': 'Invalid/missing rolename'}]}

# Rolename not a string
remove_role5_command = { 'commands': [{'command': 'removeGroupRole', 'groupname':'g', 'rolename':5 }] }
remove_role5_response = {'responses': [{'command': 'removeGroupRole', 'error': 'Invalid/missing rolename'}]}

# Rolename not UTF-8
remove_role6_command = { 'commands': [{'command': 'removeGroupRole', 'groupname': 'g', 'rolename':'￿LO' }] }
remove_role6_response = {'responses': [{'command': 'removeGroupRole', 'error': 'Role name not valid UTF-8'}]}

# Group not found
remove_role7_command = { 'commands': [{'command': 'removeGroupRole', 'groupname':'notfound', 'rolename':'notfound' }] }
remove_role7_response = {'responses': [{'command': 'removeGroupRole', 'error': 'Group not found'}]}

# Role not found
remove_role8_command = { 'commands': [{'command': 'removeGroupRole', 'groupname':'validgroup', 'rolename':'notfound' }] }
remove_role8_response = {'responses': [{'command': 'removeGroupRole', 'error': 'Role not found'}]}


# ==========================================================================
# Add client
# ==========================================================================

# No groupname
add_client1_command = { 'commands': [{'command': 'addGroupClient', 'username':'g' }] }
add_client1_response = {'responses': [{'command': 'addGroupClient', 'error': 'Invalid/missing groupname'}]}

# Groupname not a string
add_client2_command = { 'commands': [{'command': 'addGroupClient', 'groupname':5, 'username':'g' }] }
add_client2_response = {'responses': [{'command': 'addGroupClient', 'error': 'Invalid/missing groupname'}]}

# Groupname not UTF-8
add_client3_command = { 'commands': [{'command': 'addGroupClient', 'groupname': '￿LO', 'username':'g' }] }
add_client3_response = {'responses': [{'command': 'addGroupClient', 'error': 'Group name not valid UTF-8'}]}

# No username
add_client4_command = { 'commands': [{'command': 'addGroupClient', 'groupname':'g' }] }
add_client4_response = {'responses': [{'command': 'addGroupClient', 'error': 'Invalid/missing username'}]}

# Username not a string
add_client5_command = { 'commands': [{'command': 'addGroupClient', 'groupname':'g', 'username':5 }] }
add_client5_response = {'responses': [{'command': 'addGroupClient', 'error': 'Invalid/missing username'}]}

# Username not UTF-8
add_client6_command = { 'commands': [{'command': 'addGroupClient', 'groupname':'g', 'username': '￿LO' }] }
add_client6_response = {'responses': [{'command': 'addGroupClient', 'error': 'Username not valid UTF-8'}]}

# Group not found
add_client7_command = { 'commands': [{'command': 'addGroupClient', 'groupname':'notfound', 'username':'validclient' }] }
add_client7_response = {'responses': [{'command': 'addGroupClient', 'error': 'Group not found'}]}

# Client not found
add_client8_command = { 'commands': [{'command': 'addGroupClient', 'groupname':'validgroup', 'username':'notfound' }] }
add_client8_response = {'responses': [{'command': 'addGroupClient', 'error': 'Client not found'}]}


# ==========================================================================
# Remove client
# ==========================================================================

# No groupname
remove_client1_command = { 'commands': [{'command': 'removeGroupClient', 'username':'g' }] }
remove_client1_response = {'responses': [{'command': 'removeGroupClient', 'error': 'Invalid/missing groupname'}]}

# Groupname not a string
remove_client2_command = { 'commands': [{'command': 'removeGroupClient', 'groupname':5, 'username':'g' }] }
remove_client2_response = {'responses': [{'command': 'removeGroupClient', 'error': 'Invalid/missing groupname'}]}

# Groupname not UTF-8
remove_client3_command = { 'commands': [{'command': 'removeGroupClient', 'groupname':'￿LO', 'username':'g' }] }
remove_client3_response = {'responses': [{'command': 'removeGroupClient', 'error': 'Group name not valid UTF-8'}]}

# No username
remove_client4_command = { 'commands': [{'command': 'removeGroupClient', 'groupname':'g' }] }
remove_client4_response = {'responses': [{'command': 'removeGroupClient', 'error': 'Invalid/missing username'}]}

# Username not a string
remove_client5_command = { 'commands': [{'command': 'removeGroupClient', 'groupname':'g', 'username':5 }] }
remove_client5_response = {'responses': [{'command': 'removeGroupClient', 'error': 'Invalid/missing username'}]}

# Username not UTF-8
remove_client6_command = { 'commands': [{'command': 'removeGroupClient', 'groupname':'g', 'username': '￿LO' }] }
remove_client6_response = {'responses': [{'command': 'removeGroupClient', 'error': 'Username not valid UTF-8'}]}

# Group not found
remove_client7_command = { 'commands': [{'command': 'removeGroupClient', 'groupname':'notfound', 'username':'validclient' }] }
remove_client7_response = {'responses': [{'command': 'removeGroupClient', 'error': 'Group not found'}]}

# Client not found
remove_client8_command = { 'commands': [{'command': 'removeGroupClient', 'groupname':'validgroup', 'username':'notfound' }] }
remove_client8_response = {'responses': [{'command': 'removeGroupClient', 'error': 'Client not found'}]}


# ==========================================================================
# Get group
# ==========================================================================

# No groupname
get_group1_command = { 'commands': [{'command': 'getGroup'}] }
get_group1_response = {'responses': [{'command': 'getGroup', 'error': 'Invalid/missing groupname'}]}

# Groupname not a string
get_group2_command = { 'commands': [{'command': 'getGroup', 'groupname':5}] }
get_group2_response = {'responses': [{'command': 'getGroup', 'error': 'Invalid/missing groupname'}]}

# Groupname not UTF-8
get_group3_command = { 'commands': [{'command': 'getGroup', 'groupname':'￿LO' }] }
get_group3_response = {'responses': [{'command': 'getGroup', 'error': 'Group name not valid UTF-8'}]}

# Group not found
get_group4_command = { 'commands': [{'command': 'getGroup', 'groupname':"missing"}] }
get_group4_response = {'responses': [{'command': 'getGroup', 'error': 'Group not found'}]}

# ==========================================================================
# Set anon group
# ==========================================================================

# No groupname
set_anon_group1_command = { 'commands': [{'command': 'setAnonymousGroup'}] }
set_anon_group1_response = {'responses': [{'command': 'setAnonymousGroup', 'error': 'Invalid/missing groupname'}]}

# Groupname not a string
set_anon_group2_command = { 'commands': [{'command': 'setAnonymousGroup', 'groupname':5}] }
set_anon_group2_response = {'responses': [{'command': 'setAnonymousGroup', 'error': 'Invalid/missing groupname'}]}

# Groupname not UTF-8
set_anon_group3_command = { 'commands': [{'command': 'setAnonymousGroup', 'groupname':'￿LO' }] }
set_anon_group3_response = {'responses': [{'command': 'setAnonymousGroup', 'error': 'Group name not valid UTF-8'}]}

# Group not found
set_anon_group4_command = { 'commands': [{'command': 'setAnonymousGroup', 'groupname':'notfound' }] }
set_anon_group4_response = {'responses': [{'command': 'setAnonymousGroup', 'error': 'Group not found'}]}

# ==========================================================================
# Modify group
# ==========================================================================

# No groupname
modify_group1_command = { 'commands': [{'command': 'modifyGroup'}]}
modify_group1_response = {'responses': [{'command': 'modifyGroup', 'error': 'Invalid/missing groupname'}]}

# Group name not a string
modify_group2_command = { 'commands': [{'command': 'modifyGroup', 'groupname':5}]}
modify_group2_response = {'responses': [{'command': 'modifyGroup', 'error': 'Invalid/missing groupname'}]}

# Group name not UTF-8
modify_group3_command = { 'commands': [{'command': 'modifyGroup', 'groupname':'￿LO' }] }
modify_group3_response = {'responses': [{'command': 'modifyGroup', 'error': 'Group name not valid UTF-8'}]}

# roles not a list
modify_group4_command = { 'commands': [{'command': 'modifyGroup', 'groupname':'validgroup', 'password':'test', 'roles':'string'}]}
modify_group4_response = {'responses': [{'command': 'modifyGroup', 'error': "'roles' not an array or missing/invalid rolename"}]}

# No rolename
modify_group5_command = { 'commands': [{'command': 'modifyGroup', 'groupname':'validgroup', 'roles':[{}]}]}
modify_group5_response = {'responses': [{'command': 'modifyGroup', 'error': "'roles' not an array or missing/invalid rolename"}]}

# rolename not a string
modify_group6_command = { 'commands': [{'command': 'modifyGroup', 'groupname':'validgroup', 'roles':[{'rolename':5}]}]}
modify_group6_response = {'responses': [{'command': 'modifyGroup', 'error': "'roles' not an array or missing/invalid rolename"}]}

# rolename not UTF-8
#modify_group7_command = { 'commands': [{'command': 'modifyGroup', 'groupname':'validgroup','roles':[{'rolename':'￿LO'}] }] }
#modify_group7_response = {'responses': [{'command': 'modifyGroup', 'error': 'Role name not valid UTF-8'}]}

# Group not found
modify_group8_command = { 'commands': [{'command': 'modifyGroup', 'groupname':'notfound', 'rolename':'notfound'}]}
modify_group8_response = {'responses': [{'command': 'modifyGroup', 'error': 'Group not found'}]}

# Role not found
modify_group9_command = { 'commands': [{'command': 'modifyGroup', 'groupname':'validgroup', 'roles':[{'rolename':'notfound'}]}]}
modify_group9_response = {'responses': [{'command': 'modifyGroup', 'error': 'Role not found'}]}


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

    command_check(sock, create_group1_command, create_group1_response, "1")
    command_check(sock, create_group2_command, create_group2_response, "2")
    command_check(sock, create_group3_command, create_group3_response, "3")
    command_check(sock, create_group4_command, create_group4_response, "4")
    command_check(sock, create_group5_command, create_group5_response, "5")
    command_check(sock, create_group6_command, create_group6_response, "6")
    command_check(sock, create_group7_command, create_group7_response, "7")

    command_check(sock, delete_group1_command, delete_group1_response, "1")
    command_check(sock, delete_group2_command, delete_group2_response, "2")
    command_check(sock, delete_group3_command, delete_group3_response, "3")
    command_check(sock, delete_group4_command, delete_group4_response, "4")

    command_check(sock, add_role1_command, add_role1_response, "1")
    command_check(sock, add_role2_command, add_role2_response, "2")
    command_check(sock, add_role3_command, add_role3_response, "3")
    command_check(sock, add_role4_command, add_role4_response, "4")
    command_check(sock, add_role5_command, add_role5_response, "5")
    command_check(sock, add_role6_command, add_role6_response, "6")
    command_check(sock, add_role7_command, add_role7_response, "7")
    command_check(sock, add_role8_command, add_role8_response, "8")

    command_check(sock, remove_role1_command, remove_role1_response, "1")
    command_check(sock, remove_role2_command, remove_role2_response, "2")
    command_check(sock, remove_role3_command, remove_role3_response, "3")
    command_check(sock, remove_role4_command, remove_role4_response, "4")
    command_check(sock, remove_role5_command, remove_role5_response, "5")
    command_check(sock, remove_role6_command, remove_role6_response, "6")
    command_check(sock, remove_role7_command, remove_role7_response, "7")
    command_check(sock, remove_role8_command, remove_role8_response, "8")

    command_check(sock, add_client1_command, add_client1_response, "1")
    command_check(sock, add_client2_command, add_client2_response, "2")
    command_check(sock, add_client3_command, add_client3_response, "3")
    command_check(sock, add_client4_command, add_client4_response, "4")
    command_check(sock, add_client5_command, add_client5_response, "5")
    command_check(sock, add_client6_command, add_client6_response, "6")
    command_check(sock, add_client7_command, add_client7_response, "7")
    command_check(sock, add_client8_command, add_client8_response, "8")

    command_check(sock, remove_client1_command, remove_client1_response, "1")
    command_check(sock, remove_client2_command, remove_client2_response, "2")
    command_check(sock, remove_client3_command, remove_client3_response, "3")
    command_check(sock, remove_client4_command, remove_client4_response, "4")
    command_check(sock, remove_client5_command, remove_client5_response, "5")
    command_check(sock, remove_client6_command, remove_client6_response, "6")
    command_check(sock, remove_client7_command, remove_client7_response, "7")
    command_check(sock, remove_client8_command, remove_client8_response, "8")

    command_check(sock, get_group1_command, get_group1_response, "1")
    command_check(sock, get_group2_command, get_group2_response, "2")
    command_check(sock, get_group3_command, get_group3_response, "3")
    command_check(sock, get_group4_command, get_group4_response, "4")

    command_check(sock, set_anon_group1_command, set_anon_group1_response, "1")
    command_check(sock, set_anon_group2_command, set_anon_group2_response, "2")
    command_check(sock, set_anon_group3_command, set_anon_group3_response, "3")
    command_check(sock, set_anon_group4_command, set_anon_group4_response, "4")

    command_check(sock, modify_group1_command, modify_group1_response, "1")
    command_check(sock, modify_group2_command, modify_group2_response, "2")
    command_check(sock, modify_group3_command, modify_group3_response, "3")
    command_check(sock, modify_group4_command, modify_group4_response, "4")
    command_check(sock, modify_group5_command, modify_group5_response, "5")
    command_check(sock, modify_group6_command, modify_group6_response, "6")
    #command_check(sock, modify_group7_command, modify_group7_response, "7")
    command_check(sock, modify_group8_command, modify_group8_response, "8")
    command_check(sock, modify_group9_command, modify_group9_response, "9")

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
