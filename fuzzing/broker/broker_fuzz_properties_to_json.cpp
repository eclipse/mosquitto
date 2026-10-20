// /src/mosquitto/fuzzing/apps/db_dump/db_dump_fuzz_load.cpp
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cassert>

#include "/src/mosquitto/include/mosquitto.h"                   // pulls in libcommon.h and libcommon_cjson.h in correct order
#include "/src/mosquitto/libcommon/property_common.h"           // struct mqtt5__property (mosquitto_property) definition
#include "/src/cJSON/cJSON.h"                                   // cJSON APIs

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    const uint8_t *cursor = Data;
    size_t remaining = Size;

    // Build a linked list of mosquitto_property structures from the input bytes.
    // Format (repeated as long as bytes remain):
    //   1 byte : prop_type_selector (we map this to 1..7)
    //   1 byte : identifier (0..255)
    // Depending on prop type:
    //   BYTE:       1 byte value
    //   INT16:      2 bytes (little endian)
    //   INT32:      4 bytes (little endian)
    //   VARINT:     4 bytes (little endian)
    //   BINARY:     2 bytes length (LE), then that many bytes
    //   STRING:     2 bytes length (LE), then that many bytes
    //   STRING_PAIR: 2 bytes name_len, name bytes, 2 bytes value_len, value bytes
    //
    // Lengths are clamped to avoid large allocations.

    const size_t MAX_ITEMS = 128;
    const size_t MAX_STR_LEN = 4096;

    mosquitto_property *head = NULL;
    mosquitto_property *tail = NULL;
    size_t items_created = 0;

    auto read_u8 = [&](uint8_t &out)->bool{
        if(remaining < 1) return false;
        out = *cursor;
        cursor++; remaining--;
        return true;
    };
    auto read_u16 = [&](uint16_t &out)->bool{
        if(remaining < 2) return false;
        out = (uint16_t)cursor[0] | ((uint16_t)cursor[1] << 8);
        cursor += 2; remaining -= 2;
        return true;
    };
    auto read_u32 = [&](uint32_t &out)->bool{
        if(remaining < 4) return false;
        out = (uint32_t)cursor[0] | ((uint32_t)cursor[1] << 8) | ((uint32_t)cursor[2] << 16) | ((uint32_t)cursor[3] << 24);
        cursor += 4; remaining -= 4;
        return true;
    };

    while(remaining > 0 && items_created < MAX_ITEMS) {
        uint8_t sel;
        if(!read_u8(sel)) break;
        uint8_t id;
        if(!read_u8(id)) break;

        // Allocate and zero the property
        mosquitto_property *prop = (mosquitto_property *)calloc(1, sizeof(mosquitto_property));
        if(!prop) break;

        prop->next = NULL;
        // Map selector to property type 1..7
        uint8_t prop_type = (uint8_t)((sel % 7) + 1);
        prop->property_type = prop_type;
        prop->identifier = (int)id;
        prop->client_generated = false;

        switch(prop_type){
            case MQTT_PROP_TYPE_BYTE: {
                uint8_t v = 0;
                if(!read_u8(v)) v = 0;
                prop->value.i8 = v;
                break;
            }
            case MQTT_PROP_TYPE_INT16: {
                uint16_t v = 0;
                if(!read_u16(v)) v = 0;
                prop->value.i16 = v;
                break;
            }
            case MQTT_PROP_TYPE_INT32: {
                uint32_t v = 0;
                if(!read_u32(v)) v = 0;
                prop->value.i32 = v;
                break;
            }
            case MQTT_PROP_TYPE_VARINT: {
                uint32_t v = 0;
                if(!read_u32(v)) v = 0;
                prop->value.varint = v;
                break;
            }
            case MQTT_PROP_TYPE_BINARY: {
                uint16_t len = 0;
                if(!read_u16(len)) len = 0;
                if(len > MAX_STR_LEN) len = (uint16_t)MAX_STR_LEN;
                if(len > remaining) len = (uint16_t)remaining;
                if(len){
                    // allocate binary buffer
                    prop->value.bin.len = len;
                    prop->value.bin.v = (char*)malloc((size_t)len);
                    if(prop->value.bin.v){
                        memcpy(prop->value.bin.v, cursor, len);
                        cursor += len;
                        remaining -= len;
                    }else{
                        // allocation failed, ensure consistent state
                        prop->value.bin.len = 0;
                    }
                }else{
                    prop->value.bin.len = 0;
                    prop->value.bin.v = NULL;
                }
                break;
            }
            case MQTT_PROP_TYPE_STRING: {
                uint16_t len = 0;
                if(!read_u16(len)) len = 0;
                if(len > MAX_STR_LEN) len = (uint16_t)MAX_STR_LEN;
                if(len > remaining) len = (uint16_t)remaining;
                if(len){
                    prop->value.s.len = len;
                    prop->value.s.v = (char*)malloc((size_t)len + 1);
                    if(prop->value.s.v){
                        memcpy(prop->value.s.v, cursor, len);
                        prop->value.s.v[len] = '\0';
                        cursor += len;
                        remaining -= len;
                    }else{
                        prop->value.s.len = 0;
                        prop->value.s.v = NULL;
                    }
                }else{
                    // zero-length string allowed
                    prop->value.s.len = 0;
                    prop->value.s.v = (char*)malloc(1);
                    if(prop->value.s.v) prop->value.s.v[0] = '\0';
                }
                break;
            }
            case MQTT_PROP_TYPE_STRING_PAIR: {
                // name
                uint16_t name_len = 0;
                if(!read_u16(name_len)) name_len = 0;
                if(name_len > MAX_STR_LEN) name_len = (uint16_t)MAX_STR_LEN;
                if(name_len > remaining) name_len = (uint16_t)remaining;
                if(name_len){
                    prop->name.len = name_len;
                    prop->name.v = (char*)malloc((size_t)name_len + 1);
                    if(prop->name.v){
                        memcpy(prop->name.v, cursor, name_len);
                        prop->name.v[name_len] = '\0';
                        cursor += name_len;
                        remaining -= name_len;
                    }else{
                        prop->name.len = 0;
                        prop->name.v = NULL;
                    }
                }else{
                    prop->name.len = 0;
                    prop->name.v = (char*)malloc(1);
                    if(prop->name.v) prop->name.v[0] = '\0';
                }

                // value
                uint16_t value_len = 0;
                if(!read_u16(value_len)) value_len = 0;
                if(value_len > MAX_STR_LEN) value_len = (uint16_t)MAX_STR_LEN;
                if(value_len > remaining) value_len = (uint16_t)remaining;
                if(value_len){
                    prop->value.s.len = value_len;
                    prop->value.s.v = (char*)malloc((size_t)value_len + 1);
                    if(prop->value.s.v){
                        memcpy(prop->value.s.v, cursor, value_len);
                        prop->value.s.v[value_len] = '\0';
                        cursor += value_len;
                        remaining -= value_len;
                    }else{
                        prop->value.s.len = 0;
                        prop->value.s.v = NULL;
                    }
                }else{
                    prop->value.s.len = 0;
                    prop->value.s.v = (char*)malloc(1);
                    if(prop->value.s.v) prop->value.s.v[0] = '\0';
                }
                break;
            }
            default:
                // Should not happen because we mapped to 1..7, but keep conservative behavior.
                break;
        }

        // Append to list
        if(!head){
            head = tail = prop;
        }else{
            tail->next = prop;
            tail = prop;
        }

        items_created++;
    }

    // If we created no properties from the parsing loop but we do have input bytes,
    // construct a single fallback property from the raw input so the fuzz data
    // influences execution paths of mosquitto_properties_to_json.
    if(items_created == 0 && Size > 0){
        mosquitto_property *prop = (mosquitto_property *)calloc(1, sizeof(mosquitto_property));
        if(prop){
            prop->next = NULL;
            uint8_t sel = Data[0];
            uint8_t id = (Size > 1) ? Data[1] : 0;
            uint8_t prop_type = (uint8_t)((sel % 7) + 1);
            prop->property_type = prop_type;
            prop->identifier = (int)id;
            prop->client_generated = false;

            // Use the remainder of Data (if any) to populate the value.
            const uint8_t *fb_cursor = Data + 2;
            size_t fb_remaining = (Size > 2) ? (Size - 2) : 0;

            switch(prop_type){
                case MQTT_PROP_TYPE_BYTE: {
                    uint8_t v = 0;
                    if(fb_remaining >= 1) v = fb_cursor[0];
                    prop->value.i8 = v;
                    break;
                }
                case MQTT_PROP_TYPE_INT16: {
                    uint16_t v = 0;
                    if(fb_remaining >= 2) v = (uint16_t)fb_cursor[0] | ((uint16_t)fb_cursor[1] << 8);
                    prop->value.i16 = v;
                    break;
                }
                case MQTT_PROP_TYPE_INT32: {
                    uint32_t v = 0;
                    if(fb_remaining >= 4) v = (uint32_t)fb_cursor[0] | ((uint32_t)fb_cursor[1] << 8) | ((uint32_t)fb_cursor[2] << 16) | ((uint32_t)fb_cursor[3] << 24);
                    prop->value.i32 = v;
                    break;
                }
                case MQTT_PROP_TYPE_VARINT: {
                    uint32_t v = 0;
                    if(fb_remaining >= 4) v = (uint32_t)fb_cursor[0] | ((uint32_t)fb_cursor[1] << 8) | ((uint32_t)fb_cursor[2] << 16) | ((uint32_t)fb_cursor[3] << 24);
                    prop->value.varint = v;
                    break;
                }
                case MQTT_PROP_TYPE_BINARY: {
                    uint16_t len = (uint16_t)fb_remaining;
                    if(len > MAX_STR_LEN) len = (uint16_t)MAX_STR_LEN;
                    if(len){
                        prop->value.bin.len = len;
                        prop->value.bin.v = (char*)malloc((size_t)len);
                        if(prop->value.bin.v){
                            memcpy(prop->value.bin.v, fb_cursor, len);
                        }else{
                            prop->value.bin.len = 0;
                        }
                    }else{
                        prop->value.bin.len = 0;
                        prop->value.bin.v = NULL;
                    }
                    break;
                }
                case MQTT_PROP_TYPE_STRING: {
                    uint16_t len = (uint16_t)fb_remaining;
                    if(len > MAX_STR_LEN) len = (uint16_t)MAX_STR_LEN;
                    if(len){
                        prop->value.s.len = len;
                        prop->value.s.v = (char*)malloc((size_t)len + 1);
                        if(prop->value.s.v){
                            memcpy(prop->value.s.v, fb_cursor, len);
                            prop->value.s.v[len] = '\0';
                        }else{
                            prop->value.s.len = 0;
                            prop->value.s.v = NULL;
                        }
                    }else{
                        prop->value.s.len = 0;
                        prop->value.s.v = (char*)malloc(1);
                        if(prop->value.s.v) prop->value.s.v[0] = '\0';
                    }
                    break;
                }
                case MQTT_PROP_TYPE_STRING_PAIR: {
                    // Split fb_remaining roughly in half for name/value
                    uint16_t name_len = (uint16_t)(fb_remaining / 2);
                    uint16_t value_len = (uint16_t)(fb_remaining - name_len);
                    if(name_len > MAX_STR_LEN) name_len = (uint16_t)MAX_STR_LEN;
                    if(value_len > MAX_STR_LEN) value_len = (uint16_t)MAX_STR_LEN;

                    if(name_len){
                        prop->name.len = name_len;
                        prop->name.v = (char*)malloc((size_t)name_len + 1);
                        if(prop->name.v){
                            memcpy(prop->name.v, fb_cursor, name_len);
                            prop->name.v[name_len] = '\0';
                        }else{
                            prop->name.len = 0;
                            prop->name.v = NULL;
                        }
                    }else{
                        prop->name.len = 0;
                        prop->name.v = (char*)malloc(1);
                        if(prop->name.v) prop->name.v[0] = '\0';
                    }

                    if(value_len){
                        prop->value.s.len = value_len;
                        prop->value.s.v = (char*)malloc((size_t)value_len + 1);
                        if(prop->value.s.v){
                            memcpy(prop->value.s.v, fb_cursor + name_len, value_len);
                            prop->value.s.v[value_len] = '\0';
                        }else{
                            prop->value.s.len = 0;
                            prop->value.s.v = NULL;
                        }
                    }else{
                        prop->value.s.len = 0;
                        prop->value.s.v = (char*)malloc(1);
                        if(prop->value.s.v) prop->value.s.v[0] = '\0';
                    }
                    break;
                }
                default:
                    break;
            }

            head = tail = prop;
            items_created = 1;
        }
    }

    // Call the function under test.
    // It may return NULL; if it returns a cJSON object, free it.
    cJSON *json = mosquitto_properties_to_json(head);
    if(json){
        cJSON_Delete(json);
    }

    // Free the properties list. Use the library provided free function to get realistic cleanup.
    // mosquitto_property_free_all is declared in libcommon properties header.
    mosquitto_property_free_all(&head);

    // Sanity: head should now be NULL.
    // (We don't assert because fuzzer runs shouldn't abort unexpectedly.)
    (void)head;

    return 0;
}
