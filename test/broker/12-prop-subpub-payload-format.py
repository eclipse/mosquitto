#!/usr/bin/env python3

# Test whether a client subscribed to a topic receives its own message sent to that topic.
# Does the Payload Format Indicator property get sent through?
# MQTT v5

import prop_subpub_helper as helper
from mosq_test_helper import *

def do_test(start_broker):
    props_out = mqtt5_props.gen_byte_prop(mqtt5_props.PROP_PAYLOAD_FORMAT_INDICATOR, 0xed)
    props_out = props_out+mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS, 1)

    props_in = mqtt5_props.gen_byte_prop(mqtt5_props.PROP_PAYLOAD_FORMAT_INDICATOR, 0xed)

    return helper.prop_subpub_helper(start_broker, "12-prop-subpub-payload-format", props_out, props_in, expect_proto_error=True)


def all_tests(start_broker=False):
    return do_test(start_broker)

if __name__ == '__main__':
    all_tests(True)
