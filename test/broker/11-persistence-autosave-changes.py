#!/usr/bin/env python3

# Test whether a client subscribed to a topic receives its own message sent to that topic.

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("persistence true\n")
        f.write("persistence_file mosquitto-%d.db\n" % (port))
        f.write("autosave_interval 1\n")
        f.write("autosave_on_changes true\n")

def do_test():
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    rc = 1
    connect_packet = mosq_test.gen_connect("persistent-test", clean_session=True)
    connack_packet = mosq_test.gen_connack(rc=0)

    publish_packet = mosq_test.gen_publish("subpub/qos1", qos=1, mid=1, payload="message", retain=True)
    puback_packet = mosq_test.gen_puback(1)

    if os.path.exists('mosquitto-%d.db' % (port)):
        os.unlink('mosquitto-%d.db' % (port))

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")
        sock.close()

        time.sleep(0.5)
        if os.path.exists('mosquitto-%d.db' % (port)):
            rc = 0
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if os.path.exists('mosquitto-%d.db' % (port)):
            os.unlink('mosquitto-%d.db' % (port))
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)


do_test()
exit(0)

