#!/usr/bin/env python3

from mosq_test_helper import *

source_dir = Path(__file__).resolve().parent
ssl_dir = source_dir.parent / "ssl"

def write_config(filename, port1, port2):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("connection bridge_test\n")
        f.write("address 127.0.0.1:%d\n" % (port1))
        f.write("topic bridge/# both 0\n")
        f.write("notifications false\n")
        f.write("restart_timeout 2\n")
        f.write("\n")
        f.write(f"bridge_cafile {ssl_dir}/all-ca.crt\n")
        f.write("bridge_insecure true\n")

(port1, port2) = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port1, port2)

rc = 1
client_id = socket.gethostname()+".bridge_test"
connect_packet = mosq_test.gen_connect(client_id, clean_session=False, proto_ver=128+4)
connack_packet = mosq_test.gen_connack(rc=0)

mid = 1
subscribe_packet = mosq_test.gen_subscribe(mid, "bridge/#", 0)
suback_packet = mosq_test.gen_suback(mid, 0)

publish_packet = mosq_test.gen_publish("bridge/ssl/test", qos=0, payload="message")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ssock = ssl.wrap_socket(
    sock,
    ca_certs=ssl_dir / "all-ca.crt",
    keyfile=ssl_dir / "server.key",
    certfile=ssl_dir / "server.crt",
    server_side=True
)
ssock.settimeout(20)
ssock.bind(('', port1))
ssock.listen(5)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

try:
    (bridge, address) = ssock.accept()
    bridge.settimeout(20)

    mosq_test.expect_packet(bridge, "connect", connect_packet)
    bridge.send(connack_packet)

    mosq_test.expect_packet(bridge, "subscribe", subscribe_packet)
    bridge.send(suback_packet)

    pub = subprocess.Popen([f'{source_dir}/08-ssl-bridge-helper.py', str(port2)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pub.wait()
    (stdo, stde) = pub.communicate()

    mosq_test.expect_packet(bridge, "publish", publish_packet)
    rc = 0

    bridge.close()
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    try:
        bridge.close()
    except NameError:
        pass

    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))
    ssock.close()

exit(rc)
