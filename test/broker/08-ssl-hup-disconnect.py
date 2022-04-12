#!/usr/bin/env python3

# Test whether a client connected with a client certificate when
# use_identity_as_username is true is then disconnected when a SIGHUP is
# received.
# https://github.com/eclipse/mosquitto/issues/1402

from mosq_test_helper import *
import signal

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

def write_config(filename, pw_file, port, option):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("cafile ../ssl/all-ca.crt\n")
        f.write("certfile ../ssl/server.crt\n")
        f.write("keyfile ../ssl/server.key\n")
        f.write("require_certificate true\n")
        f.write("%s true\n" % (option))
        f.write("password_file %s\n" % (pw_file))

def write_pwfile(filename):
    with open(filename, 'w') as f:
        # Username "test client", password test
        f.write('test client:$6$njERlZMi/7DzNB9E$iiavfuXvUm8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==\n')

def do_test(option):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    pw_file = os.path.basename(__file__).replace('.py', '.pwfile')
    write_config(conf_file, pw_file, port, option)
    write_pwfile(pw_file)

    rc = 1
    connect_packet = mosq_test.gen_connect("connect-success-test")
    connack_packet = mosq_test.gen_connack(rc=0)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port, use_conf=True)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssock = ssl.wrap_socket(sock, ca_certs="../ssl/test-root-ca.crt", certfile="../ssl/client.crt", keyfile="../ssl/client.key", cert_reqs=ssl.CERT_REQUIRED)
        ssock.settimeout(20)
        ssock.connect(("localhost", port))
        mosq_test.do_send_receive(ssock, connect_packet, connack_packet, "connack")

        broker.send_signal(signal.SIGHUP)
        time.sleep(1)

        # This will fail if we've been disconnected
        mosq_test.do_ping(ssock)
        rc = 0

        ssock.close()
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        os.remove(pw_file)
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)

do_test("use_identity_as_username")
do_test("use_subject_as_username")
exit(0)

