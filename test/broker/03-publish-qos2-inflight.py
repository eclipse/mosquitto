#!/usr/bin/env python

# Test whether a PUBLISH to a topic with an offline subscriber results in max_inflight_messages = 1
import string
import time

try:
    import paho.mqtt.client
    import paho.mqtt.publish
except ImportError:
    print("WARNING: paho.mqtt module not available, skipping byte count test.")
    exit(0)


import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

message_current = 'misc'
message_last = 'misc'
message_in_order = True

rc = 1

def on_log(client, userdata, level, buf):
    # check messages in-order
    # message_in_order keep False after it turns False
    global message_current, message_last, message_in_order
    # Delete comment if you want to confirm actual messages 
    #print(buf)
    if message_in_order:
        message_last = message_current
        if 'PUBLISH' in buf:
            message_current = 'PUBLISH'
            message_in_order = ((message_last == 'PUBACK') or (message_last == 'PUBCOMP') or (message_last == 'misc'))
            # Wait for inducing out-of-order
            time.sleep(1)
        elif 'PUBACK' in buf:
            message_current = 'PUBACK'
            message_in_order = (message_last == 'PUBLISH')
        elif 'PUBREC' in buf:
            message_current = 'PUBREC'
            message_in_order = (message_last == 'PUBLISH')
        elif 'PUBREL' in buf:
            message_current = 'PUBREL'
            message_in_order = (message_last == 'PUBREC')
            # Wait for inducing out-of-order
            time.sleep(1)
        elif 'PUBCOMP' in buf:
            message_current = 'PUBCOMP'
            message_in_order = (message_last == 'PUBREL')
        else:
            message_current = 'misc'

qos = 2
broker = mosq_test.start_broker(filename=os.path.basename(__file__))

try:
    client = paho.mqtt.client.Client("sub-qos2-offline", clean_session=False)
    client.on_log = on_log
    client.connect("localhost", port=1888)
    client.subscribe("test/publish/inflight/#", qos)
    time.sleep(1)

    # publish 5 messages, should be receive in-order
    msgs_5 = [("test/publish/inflight/%d" % x,
         'message', qos, False) for x in range(1, 5+1)]
    paho.mqtt.publish.multiple(msgs_5, port=1888)
    
    first = time.time()
    while time.time() - 10 < first:
        client.loop(timeout=0.5)

    client.disconnect()
    if message_in_order:
        rc = 0

finally:
    broker.terminate()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde)

exit(rc)

