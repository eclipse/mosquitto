#!/usr/bin/env python3

from mosq_test_helper import *
import json

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("plugin ../../plugins/dynamic-security/mosquitto_dynamic_security.so\n")
        f.write("plugin_opt_config_file %d/dynamic-security.json\n" % (port))

def command_check(sock, command_payload, expected_response):
    command_packet = mosq_test.gen_publish(topic="$CONTROL/dynamic-security/v1", qos=0, payload=json.dumps(command_payload))
    sock.send(command_packet)
    response = json.loads(mosq_test.read_publish(sock))
    if response != expected_response:
        print(expected_response)
        print(response)
        raise ValueError(response)



port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

add_client_command = { "commands": [{
            "command": "createClient", "username": "user_one",
            "password": "password", "clientid": "cid",
            "textName": "Name", "textDescription": "Description",
            "roleName": "", "correlationData": "2" }]
}
add_client_response = {'responses': [{'command': 'createClient', 'correlationData': '2'}]}
add_client_repeat_response = {'responses':[{"command":"createClient","error":"Client already exists", "correlationData":"2"}]}

list_clients_command = { "commands": [{
            "command": "listClients", "verbose": False, "correlationData": "10"}]
}
list_clients_response = {'responses': [{"command": "listClients", "data":{"totalCount":1, "clients":["user_one"]},"correlationData":"10"}]}

list_clients_verbose_command = { "commands": [{
            "command": "listClients", "verbose": True, "correlationData": "20"}]
}
list_clients_verbose_response = {'responses':[{"command": "listClients", "data":{"totalCount":1, "clients":[
    {"username":"user_one", "clientid":"cid", "textName":"Name", "textDescription":"Description",
        "groups":[], "roles":[]}]}, "correlationData":"20"}]}


get_client_command = { "commands": [{
            "command": "getClient", "username": "user_one"}]}
get_client_response = {'responses':[{'command': 'getClient', 'data': {'client': {'username': 'user_one', 'clientid': 'cid',
            'textName': 'Name', 'textDescription': 'Description', 'groups': [], 'roles': []}}}]}

set_client_password_command = {"commands": [{
    "command": "setClientPassword", "username": "user_one", "password": "password"}]}
set_client_password_response = {"responses": [{"command":"setClientPassword"}]}

delete_client_command = { "commands": [{
            "command": "deleteClient", "username": "user_one"}]}
delete_client_response = {'responses':[{'command': 'deleteClient'}]}


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
        f.write('{"defaultACLAction": {"publishClientToBroker":"allow", "publishBrokerToClient":"allow", "subscribe":"allow", "unsubscribe":"allow"}}')
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
    command_check(sock, add_client_command, add_client_response)

    # List clients non-verbose
    command_check(sock, list_clients_command, list_clients_response)

    # List clients verbose
    command_check(sock, list_clients_verbose_command, list_clients_verbose_response)

    # Kill broker and restart, checking whether our changes were saved.
    broker.terminate()
    broker.wait()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    # Get client
    command_check(sock, get_client_command, get_client_response)

    # List clients non-verbose
    command_check(sock, list_clients_command, list_clients_response)

    # List clients verbose
    command_check(sock, list_clients_verbose_command, list_clients_verbose_response)

    # Add duplicate client
    command_check(sock, add_client_command, add_client_repeat_response)

    # Set client password
    command_check(sock, set_client_password_command, set_client_password_response)

    # Delete client
    command_check(sock, delete_client_command, delete_client_response)

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
