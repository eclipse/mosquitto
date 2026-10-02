#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>

#include "libmosquitto_mock.hpp"
#include "temperature_conversion.h"

namespace t = testing;

class TemperatureConversionTest : public ::t::Test
{
public:
	::t::NiceMock<LibMosquittoMock> libmosquitto_mock_{};


	/* Deliver a message to on_message() with a payload allocated the same way
	 * as libmosquitto does it: NULL for an empty payload, otherwise
	 * payloadlen+1 bytes with a terminating zero. */
	void deliver(const char *payload, const char *expected)
	{
		mqtt_tempconv tempconv("tempconv-test", "localhost", 1883);
		struct mosquitto_message message;
		char topic[] = "temperature/celsius";

		memset(&message, 0, sizeof(message));
		message.topic = topic;
		message.payloadlen = (int)strlen(payload);
		if(message.payloadlen > 0){
			message.payload = calloc((size_t)message.payloadlen+1, 1);
			ASSERT_NE(message.payload, nullptr);
			memcpy(message.payload, payload, (size_t)message.payloadlen);
		}

		EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::_, t::_,
				t::StrEq("temperature/fahrenheit"), (int)strlen(expected),
				t::StrEq(expected), 0, false));

		tempconv.on_message(&message);

		free(message.payload);
	}
};


TEST_F(TemperatureConversionTest, EmptyPayload)
{
	deliver("", "32.000000");
}


TEST_F(TemperatureConversionTest, ShortPayload)
{
	deliver("21", "69.800000");
}


TEST_F(TemperatureConversionTest, LongPayload)
{
	deliver("100.0000000000000000000000000000000000000000000000000000000000",
			"212.000000");
}
