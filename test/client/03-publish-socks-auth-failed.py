#!/usr/bin/env python3

#

from mosq_test_helper import *

mosq_test.require_features(["WITH_BROKER", "WITH_SOCKS"])

def do_test(proto_ver, host):
    rc = 1

    (port1, port2) = mosq_test.get_port(2)

    cmd = ['microsocks', '-?']
    try:
        proxy = subprocess.run(cmd, capture_output=True)
    except FileNotFoundError:
        print("microsocks not found, skipping test")
        sys.exit(0)

    cmd = ['microsocks', '-1', '-i', host, '-u', 'user', '-P', 'pass:word', '-p', str(port1)]
    if b"bindaddr" in proxy.stderr:
        cmd += ['-b', host]
    else:
        cmd += ['-b']

    try:
        proxy = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("microsocks not found, skipping test")
        sys.exit(0)

    if proto_ver == 5:
        V = 'mqttv5'
    elif proto_ver == 4:
        V = 'mqttv311'
    else:
        V = 'mqttv31'

    env = {
        'XDG_CONFIG_HOME':'/tmp/missing'
    }
    env = mosq_test.env_add_ld_library_path(env)
    cmd = [
            mosq_paths.mosquitto_pub,
            '-h', host,
            '-p', str(port2),
            '-q', '1',
            '-t', '03/pub/proxy/test',
            '-m', 'message',
            '-V', V,
            '--proxy', f'socks5h://wrong:auth@{host}:{port1}'
            ]

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, checkhost=host)

    try:
        pub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        pub_terminate_rc = 0
        if mosq_test.wait_for_subprocess(pub):
            print("pub not terminated")
            pub_terminate_rc = 1
        (stdo, stde) = pub.communicate()

        if stde.decode('utf-8') == 'Error: Authorisation failed\n':
            rc = 0
        else:
            rc = pub_terminate_rc
    except mosq_test.TestError:
        pass
    except Exception as e:
        print(e)
    finally:
        proxy.terminate()
        mosq_test.terminate_broker(broker)
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


do_test(proto_ver=3, host="localhost")
do_test(proto_ver=4, host="localhost")
do_test(proto_ver=5, host="localhost")
