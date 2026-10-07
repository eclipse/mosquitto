import json
import mosq_test
import mqtt_packets


def command_check(sock, command_payload, expected_response, msg=""):
    command_packet = mqtt_packets.gen_publish(topic="$CONTROL/dynamic-security/v1", qos=0, payload=json.dumps(command_payload))
    sock.send(command_packet)
    response = json.loads(mosq_test.read_publish(sock))
    if response != expected_response:
        if msg != "":
            print(msg)
        print(expected_response)
        print(response)
        raise ValueError(response)

def check_details(sock, client_count, group_count, role_count, change_index):
    command = {"commands":[{ "command": "getDetails"}]}
    response = {'responses': [{'command': 'getDetails', 'data':{
        'clientCount':client_count,
        'groupCount':group_count,
        'roleCount':role_count,
        'changeIndex': change_index
    }}]}
    command_check(sock, command, response)
