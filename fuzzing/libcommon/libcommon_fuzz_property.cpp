#include "src/libfuzzer/libfuzzer_macro.h"

#include "libcommon_fuzz_property.pb.h"
#include "mosquitto.h"

extern int32_t fuzz_memory_check_limit;
extern int32_t fuzz_memory_check_count;

DEFINE_PROTO_FUZZER(const fuzz_property::FuzzerInput& fuzzer_input)
{
	mosquitto_property *prop_list = nullptr;
	mosquitto_property *prop_copy = nullptr;

	fuzz_memory_check_count = 0;
	fuzz_memory_check_limit = fuzzer_input.memory_check_limit();

	for(const fuzz_property::Property& property : fuzzer_input.properties()){
		int identifier = property.identifier();
		switch(property.data_case()){
			case fuzz_property::Property::DataCase::kUint8Value:
				mosquitto_property_add_byte(&prop_list, identifier, property.uint8_value() % 256);
				break;
			case fuzz_property::Property::DataCase::kUint16Value:
				mosquitto_property_add_int16(&prop_list, identifier, property.uint16_value() % 65536);
				break;
			case fuzz_property::Property::DataCase::kUint32Value:
				mosquitto_property_add_int32(&prop_list, identifier, property.uint32_value());
				break;
			case fuzz_property::Property::DataCase::kVarintValue:
				mosquitto_property_add_varint(&prop_list, identifier, property.varint_value());
				break;
			case fuzz_property::Property::DataCase::kBinaryValue:
				mosquitto_property_add_binary(&prop_list, identifier,
						property.binary_value().c_str(),
						property.binary_value().size());
				break;
			case fuzz_property::Property::DataCase::kStringValue:
				mosquitto_property_add_string(&prop_list, identifier, property.string_value().c_str());
				break;
			case fuzz_property::Property::DataCase::kStringpairValue:
				mosquitto_property_add_string_pair(&prop_list, identifier,
						property.stringpair_value().name().c_str(),
						property.stringpair_value().value().c_str());
				break;
			case fuzz_property::Property::DataCase::DATA_NOT_SET:
				break;
		}
	}

	mosquitto_property_copy_all(&prop_copy, prop_list);
	mosquitto_property_free_all(&prop_list);
	mosquitto_property_free_all(&prop_copy);
}
