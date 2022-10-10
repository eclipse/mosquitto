#!/usr/bin/env python3

from mosq_test_helper import *

port = mosq_test.get_lib_port()

rc = 1
keepalive = 60
connect_packet = mosq_test.gen_connect("publish-qos2-test", keepalive=keepalive)
connack_packet = mosq_test.gen_connack(rc=0)

disconnect_packet = mosq_test.gen_disconnect()

pubrel_unexpected = mosq_test.gen_pubrel(1000)
pubcomp_unexpected = mosq_test.gen_pubcomp(1000)

mid = 13423
publish_packet = mosq_test.gen_publish("pub/qos2/receive", qos=2, mid=mid, payload="message")
pubrec_packet = mosq_test.gen_pubrec(mid)
pubrel_packet = mosq_test.gen_pubrel(mid)
pubcomp_packet = mosq_test.gen_pubcomp(mid)

publish_quit_packet = mosq_test.gen_publish("quit", qos=0, payload="quit")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.settimeout(10)
sock.bind(('', port))
sock.listen(5)

client_args = sys.argv[1:]
env = dict(os.environ)
env['LD_LIBRARY_PATH'] = mosq_test.get_build_root() + '/lib:' + mosq_test.get_build_root() + '/lib/cpp'
try:
    pp = env['PYTHONPATH']
except KeyError:
    pp = ''
env['PYTHONPATH'] = mosq_test.get_build_root() + '/lib/python:'+pp
client = mosq_test.start_client(filename=sys.argv[1].replace('/', '-'), cmd=client_args, env=env, port=port)

try:
    (conn, address) = sock.accept()
    conn.settimeout(10)

    if mosq_test.expect_packet(conn, "connect", connect_packet):
        conn.send(connack_packet)

        conn.send(pubrel_unexpected)
        if mosq_test.expect_packet(conn, "pubcomp", pubcomp_unexpected):

            conn.send(publish_packet)

            if mosq_test.expect_packet(conn, "pubrec", pubrec_packet):
                conn.send(pubrel_packet)

                if mosq_test.expect_packet(conn, "pubcomp", pubcomp_packet):
                    conn.send(publish_quit_packet)
                    rc = 0

    conn.close()
finally:
    for i in range(0, 5):
        if client.returncode != None:
            break
        time.sleep(0.1)

    if mosq_test.wait_for_subprocess(client):
        print("test client not finished")
        rc=1
    sock.close()
    if client.returncode != 0:
        exit(1)

exit(rc)
