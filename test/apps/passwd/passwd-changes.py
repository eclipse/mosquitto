#!/usr/bin/env python3

from mosq_test_helper import *
import json
import shutil
import signal

def write_config(filename, pw_file, port):
    with open(filename, 'w') as f:
        f.write(f"listener {port}\n")
        f.write("allow_anonymous false\n")
        f.write(f"password_file {pw_file}\n")

def client_check(port, username, password, rc):
    connect_packet = mosq_test.gen_connect("pwd-test", username=username, password=password)
    connack_packet = mosq_test.gen_connack(rc=rc)
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    sock.close()


def passwd_cmd(args, port, response=None, input=None):
    proc = subprocess.run([mosq_test.get_build_root()+"/apps/mosquitto_passwd/mosquitto_passwd"]
                    + args,
                    capture_output=True, encoding='utf-8', timeout=2, input=input)

    if response is not None:
        if proc.stdout != response:
            print(len(proc.stdout))
            print(len(response))
            raise ValueError(proc.stdout)

    if proc.returncode != 0:
        raise ValueError(args)


port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
pw_file = os.path.basename(__file__).replace('.py', '.pwfile')
write_config(conf_file, pw_file, port)

# Generate initial password file
passwd_cmd(["-H", "sha512", "-c", "-b", pw_file, "user1", "pass1"], port)
passwd_cmd(["-H", "sha512-pbkdf2", pw_file, "user2"], port, input="cmd\ncmd\n")

# Then start broker
broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port, nolog=True)

try:
    rc = 1
    client_check(port, "user1", "badpass", 5)
    client_check(port, "user1", "pass1", 0)
    client_check(port, "user2", "badpass", 5)
    client_check(port, "user2", "cmd", 0)
    client_check(port, "user3", "badpass", 5)
    client_check(port, "user3", "goodpass", 5)

    # Update password
    passwd_cmd(["-H", "sha512-pbkdf2", "-b", pw_file, "user1", "newpass"], port)
    broker.send_signal(signal.SIGHUP)

    client_check(port, "user1", "badpass", 5)
    client_check(port, "user1", "newpass", 0)
    client_check(port, "user2", "badpass", 5)
    client_check(port, "user2", "cmd", 0)
    client_check(port, "user3", "badpass", 5)
    client_check(port, "user3", "goodpass", 5)

    # New user
    passwd_cmd(["-b", pw_file, "user3", "goodpass"], port)
    broker.send_signal(signal.SIGHUP)

    client_check(port, "user1", "badpass", 5)
    client_check(port, "user1", "newpass", 0)
    client_check(port, "user2", "badpass", 5)
    client_check(port, "user2", "cmd", 0)
    client_check(port, "user3", "badpass", 5)
    client_check(port, "user3", "goodpass", 0)

    # Delete user
    passwd_cmd(["-D", pw_file, "user2"], port)
    broker.send_signal(signal.SIGHUP)

    client_check(port, "user1", "badpass", 5)
    client_check(port, "user1", "newpass", 0)
    client_check(port, "user2", "badpass", 5)
    client_check(port, "user2", "cmd", 5)
    client_check(port, "user3", "badpass", 5)
    client_check(port, "user3", "goodpass", 0)

    rc = 0
except mosq_test.TestError:
    pass
except Exception as err:
    print(err)
finally:
    os.remove(conf_file)
    os.remove(pw_file)
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1

exit(rc)
