#!/usr/bin/env python3

# Test whether a valid CONNECT results in the correct CONNACK packet using an
# SSL connection with client certificates required.

from mosq_test_helper import *

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

def write_config(filename, port1, port2):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("\n")
        f.write("listener %d\n" % (port1))
        f.write(f"cafile {ssl_dir}/all-ca.crt\n")
        f.write(f"certfile {ssl_dir}/server.crt\n")
        f.write(f"keyfile {ssl_dir}/server.key\n")
        f.write("require_certificate true\n")

(port1, port2) = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port1, port2)

rc = 1
connect_packet = mosq_test.gen_connect("connect-success-test")

broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock = ssl.wrap_socket(sock, ca_certs=f"{ssl_dir}/test-root-ca.crt", certfile=f"{ssl_dir}/client-expired.crt", keyfile=f"{ssl_dir}/client-expired.key", cert_reqs=ssl.CERT_REQUIRED)
    ssock.settimeout(20)
    try:
        ssock.connect(("localhost", port1))
        mosq_test.do_send_receive(ssock, connect_packet, "", "connack")
    except ssl.SSLError as err:
        if err.errno == 1:
            rc = 0
        else:
            broker.terminate()
            raise ValueError(err.errno)
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    time.sleep(0.5)
    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))

exit(rc)

