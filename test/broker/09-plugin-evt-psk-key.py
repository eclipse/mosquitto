#!/usr/bin/env python3

# Test whether a plugin can subscribe to the tick event

from mosq_test_helper import *

def write_config(filename, port, per_listener_settings="false"):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener_settings))
        f.write("listener %d\n" % (port))
        f.write("plugin c/plugin_evt_psk_key.so\n")
        f.write("psk_hint myhint\n")
        f.write("allow_anonymous true\n")


def do_test(per_listener_settings):
    rc = 1
    proto_ver = 5
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, per_listener_settings)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        bad_client_args = [mosq_test.get_build_root() + '/client/mosquitto_pub',
                '-t', 'plugin/psk/test',
                '-m', 'psk-test',
                '--psk', '159445',
                '--psk-identity', 'badidentity',
                '-p', str(port)]
        bad_client = mosq_test.start_client(filename=sys.argv[0].replace('/', '-'), cmd=bad_client_args)
        bad_client.wait()
        if bad_client.returncode == 0:
            raise ValueError('bad client should have failed')

        sub_client_args = [mosq_test.get_build_root() + '/client/mosquitto_sub',
                '-t', 'plugin/psk/test',
                '-C', '1',
                '-W', '2',
                '--psk', '159445',
                '--psk-identity', 'subidentity',
                '-v', '-N',
                '-p', str(port)]
        sub_client = mosq_test.start_client(filename=sys.argv[0].replace('/', '-'), cmd=sub_client_args)

        pub_client_args = [mosq_test.get_build_root() + '/client/mosquitto_pub',
                '-t', 'plugin/psk/test',
                '-m', 'psk-test',
                '--psk', '297A49',
                '--psk-identity', 'pubidentity',
                '-p', str(port)]
        pub_client = mosq_test.start_client(filename=sys.argv[0].replace('/', '-'), cmd=pub_client_args)
        pub_client.wait()
        sub_client.wait()

        if pub_client.returncode == 0 and sub_client.returncode == 0:
            (stdo, _) = sub_client.communicate()
            if stdo.decode('utf-8') != "plugin/psk/test psk-test":
                raise ValueError(stdo.decode('utf-8'))

        rc = 0
    except mosq_test.TestError:
        pass
    except Exception as err:
        print(err)
    finally:
        os.remove(conf_file)
        broker.terminate()
        broker.wait()
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)

do_test("false")
do_test("true")
