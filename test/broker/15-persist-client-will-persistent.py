#!/usr/bin/env python3

# Connect a client, add a subscription, disconnect, send a message with a
# different client, restore, reconnect, check it is received.

from mosq_test_helper import *
from persist_client_will_core import do_test

send_will_disconnect_rc = mqtt5_rc.DISCONNECT_WITH_WILL_MSG
normal_disconnect_rc = mqtt5_rc.NORMAL_DISCONNECTION

# Run test with different parameters:
# If disconnect_rc is not set the client will not disconnect
# session_expiry, will qos, will retain, disconnect_rc

send_will_disconnect_rc = mqtt5_rc.DISCONNECT_WITH_WILL_MSG

# persistent client connected during crash
do_test(60, 0, 0)
do_test(60, 1, 0)
do_test(60, 0, 1)
do_test(60, 1, 1)

# persistent client connected during crash with a will delay of 30 seconds
do_test(60, 0, 0, will_delay=30)
do_test(60, 1, 0, will_delay=30)
do_test(60, 0, 1, will_delay=30)
do_test(60, 1, 1, will_delay=30)

# persistent client disconnecting with will sent before crash
do_test(60, 0, 0, disconnect_rc=send_will_disconnect_rc)
do_test(60, 1, 0, disconnect_rc=send_will_disconnect_rc)
do_test(60, 0, 1, disconnect_rc=send_will_disconnect_rc)
do_test(60, 1, 1, disconnect_rc=send_will_disconnect_rc)

# persistent client disconnecting without will sent before crash
do_test(60, 0, 0, disconnect_rc=normal_disconnect_rc)
do_test(60, 1, 0, disconnect_rc=normal_disconnect_rc)
do_test(60, 0, 1, disconnect_rc=normal_disconnect_rc)
do_test(60, 1, 1, disconnect_rc=normal_disconnect_rc)

# persistent client disconnecting with will sent, but will delay
do_test(60, 0, 0, will_delay=30, disconnect_rc=send_will_disconnect_rc)
do_test(60, 1, 0, will_delay=30, disconnect_rc=send_will_disconnect_rc)
do_test(60, 0, 1, will_delay=30, disconnect_rc=send_will_disconnect_rc)
do_test(60, 1, 1, will_delay=30, disconnect_rc=send_will_disconnect_rc)

# Remove will msg by session takeover through reconnect
do_test(0, 1, 1, disconnect_rc=mqtt5_rc.SESSION_TAKEN_OVER)
# do_test(60, 1, 1, disconnect_rc=mqtt5_rc.SESSION_TAKEN_OVER)
