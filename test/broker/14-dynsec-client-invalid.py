#!/usr/bin/env python3

# Check invalid inputs for client commands

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

# ==========================================================================
# Create client
# ==========================================================================

# No username
create_client1_command = { 'commands': [{'command': 'createClient' }] }
create_client1_response = {'responses': [{'command': 'createClient', 'error': 'Invalid/missing username'}]}

# Username not a string
create_client2_command = { 'commands': [{'command': 'createClient', 'username': 5 }] }
create_client2_response = {'responses': [{'command': 'createClient', 'error': 'Invalid/missing username'}]}

# Username not UTF-8
create_client3_command = { 'commands': [{'command': 'createClient', 'username': '￿LO' }] }
create_client3_response = {'responses': [{'command': 'createClient', 'error': 'Username not valid UTF-8'}]}

# Password not a string
create_client4_command = { 'commands': [{'command': 'createClient', 'username': 'user', 'password':5 }] }
create_client4_response = {'responses': [{'command': 'createClient', 'error': 'Invalid/missing password'}]}

# Client id not a string
create_client5_command = { 'commands': [{'command': 'createClient', 'username': 'user', 'password':'5', 'clientid':5}] }
create_client5_response = {'responses': [{'command': 'createClient', 'error': 'Invalid/missing client id'}]}

# Client id not UTF-8
create_client6_command = { 'commands': [{'command': 'createClient', 'username': 'user', 'clientid':'￿LO' }] }
create_client6_response = {'responses': [{'command': 'createClient', 'error': 'Client ID not valid UTF-8'}]}

# Text name not a string
create_client7_command = { 'commands': [{'command': 'createClient', 'username': 'user', 'password':'5', 'textname':5}] }
create_client7_response = {'responses': [{'command': 'createClient', 'error': 'Invalid/missing textname'}]}

# Text description not a string
create_client8_command = { 'commands': [{'command': 'createClient', 'username': 'user', 'password':'5', 'textdescription':5}] }
create_client8_response = {'responses': [{'command': 'createClient', 'error': 'Invalid/missing textdescription'}]}

# Client already exists
create_client9_command = { 'commands': [{'command': 'createClient', 'username': 'admin', 'password':'5'}]}
create_client9_response = {'responses': [{'command': 'createClient', 'error': 'Client already exists'}]}

# Roles not an array
create_client10_command = { 'commands': [{'command': 'createClient', 'username': 'user', 'password':'5', 'roles':'bad'}] }
create_client10_response = {'responses': [{'command': 'createClient', 'error': "'roles' not an array or missing/invalid rolename"}]}

# Role not found
create_client11_command = { 'commands': [{'command': 'createClient', 'username': 'user', 'password':'5', 'roles':[{'rolename':'notfound'}]}] }
create_client11_response = {'responses': [{'command': 'createClient', 'error': 'Role not found'}]}

# Group not found
create_client12_command = { 'commands': [{'command': 'createClient', 'username': 'user', 'password':'5', 'groups':[{'groupname':'notfound'}]}] }
create_client12_response = {'responses': [{'command': 'createClient', 'error': 'Group not found'}]}


# ==========================================================================
# Delete client
# ==========================================================================

# No username
delete_client1_command = { 'commands': [{'command': 'deleteClient'}]}
delete_client1_response = {'responses': [{'command': 'deleteClient', 'error': 'Invalid/missing username'}]}

# Username not a string
delete_client2_command = { 'commands': [{'command': 'deleteClient', 'username':5}]}
delete_client2_response = {'responses': [{'command': 'deleteClient', 'error': 'Invalid/missing username'}]}

# Username not UTF-8
delete_client3_command = { 'commands': [{'command': 'deleteClient', 'username': '￿LO' }] }
delete_client3_response = {'responses': [{'command': 'deleteClient', 'error': 'Username not valid UTF-8'}]}

# Client not found
delete_client4_command = { 'commands': [{'command': 'deleteClient', 'username':'notfound'}]}
delete_client4_response = {'responses': [{'command': 'deleteClient', 'error': 'Client not found'}]}

# ==========================================================================
# Disable client
# ==========================================================================

# No username
disable_client1_command = { 'commands': [{'command': 'disableClient'}]}
disable_client1_response = {'responses': [{'command': 'disableClient', 'error': 'Invalid/missing username'}]}

# Username not a string
disable_client2_command = { 'commands': [{'command': 'disableClient', 'username':5}]}
disable_client2_response = {'responses': [{'command': 'disableClient', 'error': 'Invalid/missing username'}]}

# Username not UTF-8
disable_client3_command = { 'commands': [{'command': 'disableClient', 'username': '￿LO' }] }
disable_client3_response = {'responses': [{'command': 'disableClient', 'error': 'Username not valid UTF-8'}]}

# Client not found
disable_client4_command = { 'commands': [{'command': 'disableClient', 'username':'notfound'}]}
disable_client4_response = {'responses': [{'command': 'disableClient', 'error': 'Client not found'}]}


# ==========================================================================
# Enable client
# ==========================================================================

# No username
enable_client1_command = { 'commands': [{'command': 'enableClient'}]}
enable_client1_response = {'responses': [{'command': 'enableClient', 'error': 'Invalid/missing username'}]}

# Username not a string
enable_client2_command = { 'commands': [{'command': 'enableClient', 'username':5}]}
enable_client2_response = {'responses': [{'command': 'enableClient', 'error': 'Invalid/missing username'}]}

# Username not UTF-8
enable_client3_command = { 'commands': [{'command': 'enableClient', 'username': '￿LO' }] }
enable_client3_response = {'responses': [{'command': 'enableClient', 'error': 'Username not valid UTF-8'}]}

# Client not found
enable_client4_command = { 'commands': [{'command': 'enableClient', 'username':'notfound'}]}
enable_client4_response = {'responses': [{'command': 'enableClient', 'error': 'Client not found'}]}


# ==========================================================================
# Set client id
# ==========================================================================

# No username
set_client_id1_command = { 'commands': [{'command': 'setClientId'}]}
set_client_id1_response = {'responses': [{'command': 'setClientId', 'error': 'Invalid/missing username'}]}

# Username not a string
set_client_id2_command = { 'commands': [{'command': 'setClientId', 'username':5}]}
set_client_id2_response = {'responses': [{'command': 'setClientId', 'error': 'Invalid/missing username'}]}

# Username not UTF-8
set_client_id3_command = { 'commands': [{'command': 'setClientId', 'username': '￿LO' }] }
set_client_id3_response = {'responses': [{'command': 'setClientId', 'error': 'Username not valid UTF-8'}]}

# No client id
set_client_id4_command = { 'commands': [{'command': 'setClientId', 'username':'user'}]}
set_client_id4_response = {'responses': [{'command': 'setClientId', 'error': 'Client not found'}]}

# Client id not a string
set_client_id5_command = { 'commands': [{'command': 'setClientId', 'username':'user', 'clientid':5}]}
set_client_id5_response = {'responses': [{'command': 'setClientId', 'error': 'Invalid/missing client ID'}]}

# Client id not UTF-8
set_client_id6_command = { 'commands': [{'command': 'setClientId', 'username':'user', 'clientid': '￿LO' }] }
set_client_id6_response = {'responses': [{'command': 'setClientId', 'error': 'Client ID not valid UTF-8'}]}

# Client not found
set_client_id7_command = { 'commands': [{'command': 'setClientId', 'username':'notfound', 'clientid':'newid'}]}
set_client_id7_response = {'responses': [{'command': 'setClientId', 'error': 'Client not found'}]}


# ==========================================================================
# Set password
# ==========================================================================

# No username
set_password1_command = { 'commands': [{'command': 'setClientPassword'}]}
set_password1_response = {'responses': [{'command': 'setClientPassword', 'error': 'Invalid/missing username'}]}

# Username not a string
set_password2_command = { 'commands': [{'command': 'setClientPassword', 'username':5}]}
set_password2_response = {'responses': [{'command': 'setClientPassword', 'error': 'Invalid/missing username'}]}

# Username not UTF-8
set_password3_command = { 'commands': [{'command': 'setClientPassword', 'username':'￿LO' }] }
set_password3_response = {'responses': [{'command': 'setClientPassword', 'error': 'Username not valid UTF-8'}]}

# No password
set_password4_command = { 'commands': [{'command': 'setClientPassword', 'username':'user'}]}
set_password4_response = {'responses': [{'command': 'setClientPassword', 'error': 'Invalid/missing password'}]}

# password not a string
set_password5_command = { 'commands': [{'command': 'setClientPassword', 'username':'user', 'password':5}]}
set_password5_response = {'responses': [{'command': 'setClientPassword', 'error': 'Invalid/missing password'}]}

# password is empty
set_password6_command = { 'commands': [{'command': 'setClientPassword', 'username':'user', 'password':''}]}
set_password6_response = {'responses': [{'command': 'setClientPassword', 'error': 'Empty password is not allowed'}]}

# Client not found
set_password7_command = { 'commands': [{'command': 'setClientPassword', 'username':'notfound', 'password':'newpw'}]}
set_password7_response = {'responses': [{'command': 'setClientPassword', 'error': 'Client not found'}]}


# ==========================================================================
# Get client
# ==========================================================================

# No username
get_client1_command = { 'commands': [{'command': 'getClient'}]}
get_client1_response = {'responses': [{'command': 'getClient', 'error': 'Invalid/missing username'}]}

# Username not a string
get_client2_command = { 'commands': [{'command': 'getClient', 'username':5}]}
get_client2_response = {'responses': [{'command': 'getClient', 'error': 'Invalid/missing username'}]}

# Username not UTF-8
get_client3_command = { 'commands': [{'command': 'getClient', 'username':'￿LO' }] }
get_client3_response = {'responses': [{'command': 'getClient', 'error': 'Username not valid UTF-8'}]}

# Client not found
get_client4_command = { 'commands': [{'command': 'getClient', 'username':'notfound'}]}
get_client4_response = {'responses': [{'command': 'getClient', 'error': 'Client not found'}]}


# ==========================================================================
# Add role
# ==========================================================================

# No username
add_role1_command = { 'commands': [{'command': 'addClientRole'}]}
add_role1_response = {'responses': [{'command': 'addClientRole', 'error': 'Invalid/missing username'}]}

# Username not a string
add_role2_command = { 'commands': [{'command': 'addClientRole', 'username':5}]}
add_role2_response = {'responses': [{'command': 'addClientRole', 'error': 'Invalid/missing username'}]}

# Username not UTF-8
add_role3_command = { 'commands': [{'command': 'addClientRole', 'username':'￿LO' }] }
add_role3_response = {'responses': [{'command': 'addClientRole', 'error': 'Username not valid UTF-8'}]}

# No rolename
add_role4_command = { 'commands': [{'command': 'addClientRole', 'username':'user'}]}
add_role4_response = {'responses': [{'command': 'addClientRole', 'error': 'Invalid/missing rolename'}]}

# rolename not a string
add_role5_command = { 'commands': [{'command': 'addClientRole', 'username':'user', 'rolename':5}]}
add_role5_response = {'responses': [{'command': 'addClientRole', 'error': 'Invalid/missing rolename'}]}

# rolename not UTF-8
add_role6_command = { 'commands': [{'command': 'addClientRole', 'username':'user', 'rolename':'￿LO' }] }
add_role6_response = {'responses': [{'command': 'addClientRole', 'error': 'Role name not valid UTF-8'}]}

# Client not found
add_role7_command = { 'commands': [{'command': 'addClientRole', 'username':'notfound', 'rolename':'notfound'}]}
add_role7_response = {'responses': [{'command': 'addClientRole', 'error': 'Client not found'}]}

# Role not found
add_role8_command = { 'commands': [{'command': 'addClientRole', 'username':'admin', 'rolename':'notfound'}]}
add_role8_response = {'responses': [{'command': 'addClientRole', 'error': 'Role not found'}]}


# ==========================================================================
# Remove role
# ==========================================================================

# No username
remove_role1_command = { 'commands': [{'command': 'removeClientRole'}]}
remove_role1_response = {'responses': [{'command': 'removeClientRole', 'error': 'Invalid/missing username'}]}

# Username not a string
remove_role2_command = { 'commands': [{'command': 'removeClientRole', 'username':5}]}
remove_role2_response = {'responses': [{'command': 'removeClientRole', 'error': 'Invalid/missing username'}]}

# Username not UTF-8
remove_role3_command = { 'commands': [{'command': 'removeClientRole', 'username':'￿LO' }] }
remove_role3_response = {'responses': [{'command': 'removeClientRole', 'error': 'Username not valid UTF-8'}]}

# No rolename
remove_role4_command = { 'commands': [{'command': 'removeClientRole', 'username':'user'}]}
remove_role4_response = {'responses': [{'command': 'removeClientRole', 'error': 'Invalid/missing rolename'}]}

# rolename not a string
remove_role5_command = { 'commands': [{'command': 'removeClientRole', 'username':'user', 'rolename':5}]}
remove_role5_response = {'responses': [{'command': 'removeClientRole', 'error': 'Invalid/missing rolename'}]}

# rolename not UTF-8
remove_role6_command = { 'commands': [{'command': 'removeClientRole', 'username':'user', 'rolename':'￿LO' }] }
remove_role6_response = {'responses': [{'command': 'removeClientRole', 'error': 'Role name not valid UTF-8'}]}

# Client not found
remove_role7_command = { 'commands': [{'command': 'removeClientRole', 'username':'notfound', 'rolename':'notfound'}]}
remove_role7_response = {'responses': [{'command': 'removeClientRole', 'error': 'Client not found'}]}

# Role not found
remove_role8_command = { 'commands': [{'command': 'removeClientRole', 'username':'admin', 'rolename':'notfound'}]}
remove_role8_response = {'responses': [{'command': 'removeClientRole', 'error': 'Role not found'}]}


# ==========================================================================
# Modify client
# ==========================================================================

# Create a client to modify
modify_client0_command = { 'commands': [{'command': 'createClient', 'username':'user'}]}
modify_client0_response = {'responses': [{'command': 'createClient'}]}

# No username
modify_client1_command = { 'commands': [{'command': 'modifyClient'}]}
modify_client1_response = {'responses': [{'command': 'modifyClient', 'error': 'Invalid/missing username'}]}

# Username not a string
modify_client2_command = { 'commands': [{'command': 'modifyClient', 'username':5}]}
modify_client2_response = {'responses': [{'command': 'modifyClient', 'error': 'Invalid/missing username'}]}

# Username not UTF-8
modify_client3_command = { 'commands': [{'command': 'modifyClient', 'username':'￿LO' }] }
modify_client3_response = {'responses': [{'command': 'modifyClient', 'error': 'Username not valid UTF-8'}]}

# roles not a list
modify_client4_command = { 'commands': [{'command': 'modifyClient', 'username':'user', 'password':'test', 'roles':'string'}]}
modify_client4_response = {'responses': [{'command': 'modifyClient', 'error': "'roles' not an array or missing/invalid rolename"}]}

# No rolename
modify_client5_command = { 'commands': [{'command': 'modifyClient', 'username':'user', 'roles':[{'rolename':5}]}]}
modify_client5_response = {'responses': [{'command': 'modifyClient', 'error': "'roles' not an array or missing/invalid rolename"}]}

# rolename not UTF-8
#modify_client6_command = { 'commands': [{'command': 'modifyClient', 'username':'user', 'rolename':'￿LO' }] }
#modify_client6_response = {'responses': [{'command': 'modifyClient', 'error': 'Username not valid UTF-8'}]}

# Client not found
modify_client7_command = { 'commands': [{'command': 'modifyClient', 'username':'notfound', 'rolename':'notfound'}]}
modify_client7_response = {'responses': [{'command': 'modifyClient', 'error': 'Client not found'}]}

# Role not found
modify_client8_command = { 'commands': [{'command': 'modifyClient', 'username':'user', 'roles':[{'rolename':'notfound'}]}]}
modify_client8_response = {'responses': [{'command': 'modifyClient', 'error': 'Role not found'}]}


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

    command_check(sock, create_client1_command, create_client1_response, "1")
    command_check(sock, create_client2_command, create_client2_response, "2")
    command_check(sock, create_client3_command, create_client3_response, "3")
    command_check(sock, create_client4_command, create_client4_response, "4")
    command_check(sock, create_client5_command, create_client5_response, "5")
    command_check(sock, create_client6_command, create_client6_response, "6")
    command_check(sock, create_client7_command, create_client7_response, "7")
    command_check(sock, create_client8_command, create_client8_response, "8")
    command_check(sock, create_client9_command, create_client9_response, "9")
    command_check(sock, create_client10_command, create_client10_response, "10")
    command_check(sock, create_client11_command, create_client11_response, "11")
    command_check(sock, create_client12_command, create_client12_response, "12")

    command_check(sock, delete_client1_command, delete_client1_response, "1")
    command_check(sock, delete_client2_command, delete_client2_response, "2")
    #command_check(sock, delete_client3_command, delete_client3_response, "3")
    command_check(sock, delete_client4_command, delete_client4_response, "4")

    command_check(sock, disable_client1_command, disable_client1_response, "1")
    command_check(sock, disable_client2_command, disable_client2_response, "2")
    command_check(sock, disable_client3_command, disable_client3_response, "3")
    command_check(sock, disable_client4_command, disable_client4_response, "4")

    command_check(sock, enable_client1_command, enable_client1_response, "1")
    command_check(sock, enable_client2_command, enable_client2_response, "2")
    command_check(sock, enable_client3_command, enable_client3_response, "3")
    command_check(sock, enable_client4_command, enable_client4_response, "4")

    command_check(sock, set_client_id1_command, set_client_id1_response, "1")
    command_check(sock, set_client_id2_command, set_client_id2_response, "2")
    command_check(sock, set_client_id3_command, set_client_id3_response, "3")
    command_check(sock, set_client_id4_command, set_client_id4_response, "4")
    command_check(sock, set_client_id5_command, set_client_id5_response, "5")
    command_check(sock, set_client_id6_command, set_client_id6_response, "6")
    command_check(sock, set_client_id7_command, set_client_id7_response, "7")

    command_check(sock, set_password1_command, set_password1_response, "1")
    command_check(sock, set_password2_command, set_password2_response, "2")
    command_check(sock, set_password3_command, set_password3_response, "3")
    command_check(sock, set_password4_command, set_password4_response, "4")
    command_check(sock, set_password5_command, set_password5_response, "5")
    command_check(sock, set_password6_command, set_password6_response, "6")
    command_check(sock, set_password7_command, set_password7_response, "7")

    command_check(sock, get_client1_command, get_client1_response, "1")
    command_check(sock, get_client2_command, get_client2_response, "2")
    command_check(sock, get_client3_command, get_client3_response, "3")
    command_check(sock, get_client4_command, get_client4_response, "4")

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

    command_check(sock, modify_client0_command, modify_client0_response, "1")
    command_check(sock, modify_client1_command, modify_client1_response, "1")
    command_check(sock, modify_client2_command, modify_client2_response, "2")
    command_check(sock, modify_client3_command, modify_client3_response, "3")
    command_check(sock, modify_client4_command, modify_client4_response, "4")
    command_check(sock, modify_client5_command, modify_client5_response, "5")
    #command_check(sock, modify_client6_command, modify_client6_response, "6")
    command_check(sock, modify_client7_command, modify_client7_response, "7")
    command_check(sock, modify_client8_command, modify_client8_response, "8")


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
