#!/usr/bin/env python3

from mosq_test_helper import *

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

def write_config(filename, port1, port2):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")
        f.write("listener %d\n" % (port1))
        f.write("allow_anonymous true\n")
        f.write("cafile ../ssl/all-ca.crt\n")
        f.write("certfile ../ssl/server.crt\n")
        f.write("keyfile ../ssl/server.key\n")
        f.write("require_certificate true\n")
        f.write("crlfile ../ssl/crl.pem\n")

(port1, port2) = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port1, port2)

rc = 1
connect_packet = mosq_test.gen_connect("connect-revoked-test")

broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock = ssl.wrap_socket(sock, ca_certs="../ssl/test-root-ca.crt", certfile="../ssl/client-revoked.crt", keyfile="../ssl/client-revoked.key", cert_reqs=ssl.CERT_REQUIRED)
    ssock.settimeout(20)
    try:
        ssock.connect(("localhost", port1))
        mosq_test.do_send_receive(ssock, connect_packet, "", "connack")
    except ssl.SSLError as err:
        if err.errno == 1 and "certificate revoked" in err.strerror:
            rc = 0
        else:
            broker.terminate()
            print(err.strerror)
            raise ValueError(err.errno)

except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    time.sleep(0.5)
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))

exit(rc)

