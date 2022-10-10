#!/usr/bin/env python3

# Test whether a valid CONNECT results in the correct CONNACK packet using an SSL connection.

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

(port1, port2) = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port1, port2)

rc = 1
connect_packet = mosq_test.gen_connect("connect-success-test")
connack_packet = mosq_test.gen_connack(rc=0)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{ssl_dir}/test-alt-ca.crt")
ssock = context.wrap_socket(sock, server_hostname="localhost")
ssock.settimeout(20)
try:
    ssock.connect(("localhost", port1))
except ssl.SSLError as err:
    if err.errno == 1:
        rc = 0
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    ssock.close()

time.sleep(0.5)
broker.terminate()
if mosq_test.wait_for_subprocess(broker):
    print("broker not terminated")
    if rc == 0: rc=1
(stdo, stde) = broker.communicate()
if rc:
    print(stde.decode('utf-8'))
exit(rc)

