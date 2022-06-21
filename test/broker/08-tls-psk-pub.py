#!/usr/bin/env python3

from mosq_test_helper import *

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)


def write_config(filename, port1, port2):
    with open(filename, 'w') as f:
        f.write("allow_anonymous true\n")
        f.write(f"psk_file {str(source_dir/'08-tls-psk-pub.psk')}\n")
        f.write("\n")
        f.write("listener %d\n" % (port1))
        f.write("psk_hint hint\n")
        f.write("\n")
        f.write("listener %d\n" % (port2))
        f.write("log_type all\n")

(port1, port2) = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port1, port2)

env = dict(os.environ)
env['LD_LIBRARY_PATH'] = mosq_test.get_build_root() + '/lib:' + mosq_test.get_build_root() + '/lib/cpp'
try:
    pp = env['PYTHONPATH']
except KeyError:
    pp = ''
env['PYTHONPATH'] = mosq_test.get_build_root() + '/lib/python:'+pp


rc = 1
connect_packet = mosq_test.gen_connect("no-psk-test-client")
connack_packet = mosq_test.gen_connack(rc=0)

mid = 1
subscribe_packet = mosq_test.gen_subscribe(mid, "psk/test", 0)
suback_packet = mosq_test.gen_suback(mid, 0)

publish_packet = mosq_test.gen_publish(topic="psk/test", payload="message", qos=0)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port2)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port2)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    pub = subprocess.Popen(['./c/08-tls-psk-pub.test', str(port1)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if pub.wait():
        raise ValueError
    (stdo, stde) = pub.communicate()

    mosq_test.expect_packet(sock, "publish", publish_packet)
    rc = 0

    sock.close()
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))

exit(rc)

