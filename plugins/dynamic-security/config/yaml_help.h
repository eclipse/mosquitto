//
// Created by Akos Vandra on 2023-01-20.
//

#ifndef MOSQUITTO_UTIL_H
#define MOSQUITTO_UTIL_H

#include "yaml.h"
#include <stdbool.h>

#define PARSER_EXPECT_EVENT_TYPE(event, event_type, on_error) \
    if ((event)->type != event_type) { \
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error parsing Dynamic security plugin config: Expected event %s, but got %s on line %d:%d at %s:%d\n", yaml_event_type_name(event_type), yaml_event_type_name((event)->type), (event)->start_mark.line, (event)->start_mark.column, __FILE__, __LINE__);    \
        do { on_error; } while (0);                                                                                                                                                                                                                            \
    }

#define YAML_CHECK_RESULT(block, on_error, msg, ...) \
    if (!(block)) { \
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error parsing Dynamic security plugin config: " msg " from %s:%d\n" __VA_OPT__(,) __VA_ARGS__, __FILE__, __LINE__); \
        do { on_error; } while (0); \
    }

#define YAML_EVENT_INTO_SCALAR_BOOL(event, out, on_err) YAML_CHECK_RESULT(yaml_parse_bool_scalar(event, out, __FILE__, __LINE__), { do { on_err } while(0); }, "Could not parse boolean value from %s", event->data.scalar.value)
#define YAML_EVENT_INTO_SCALAR_STRING(event, out, on_err) YAML_CHECK_RESULT(yaml_parse_string_scalar(event, out), on_err, "Could not read string value")
#define YAML_EVENT_INTO_SCALAR_LONG_INT(event, out, on_err) YAML_CHECK_RESULT(yaml_parse_long_int_scalar(event, out, __FILE__, __LINE__),  { do { on_err } while(0); }, "Could not read integer value from %s", event->data.scalar.value)

#define YAML_PARSER_FOR_ALL(parser, event, start_event, end_event, on_error, ...) \
    {                                                                               \
        PARSER_EXPECT_EVENT_TYPE(event, start_event, on_error);                     \
        while(true) {                                                               \
            if (!yaml_parser_parse(parser, event)) on_error;                        \
            if ((event)->type == end_event) break;                                  \
            do { __VA_ARGS__; } while (0);                                          \
            yaml_event_delete(event);                                               \
        };                                                                          \
        yaml_event_delete(event);                                                   \
    }

#define YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, on_error, ...)  YAML_PARSER_FOR_ALL(parser, event, YAML_SEQUENCE_START_EVENT, YAML_SEQUENCE_END_EVENT, on_error, __VA_ARGS__)
#define YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, on_error, ...)  YAML_PARSER_FOR_ALL(parser, event, YAML_MAPPING_START_EVENT, YAML_MAPPING_END_EVENT, on_error, { \
    printf("1\n");                                                                                                                                                                         \
    PARSER_EXPECT_EVENT_TYPE(event, YAML_SCALAR_EVENT, on_error);                                                                                                        \
    printf("2\n");                                                                                                                                                                         \
    char *key = mosquitto_strdup((char*)(event)->data.scalar.value);                                                                                                       \
    yaml_event_delete(event);                                               \
    if (!yaml_parser_parse(parser, event)) on_error;                                                                                                                     \
    printf("3\n");                                                                                                                                                                         \
    do { __VA_ARGS__; } while (0);                                                                                                                                               \
    printf("4\n");                                                                                                                                                                         \
    mosquitto_free(key);                                                                                                                                                 \
})

char* yaml_event_type_name(yaml_event_type_t t);
void yaml_print_event(yaml_event_t *event, int level);
int yaml_emit_string_field(yaml_emitter_t *emitter, yaml_event_t *event, const char* field, const char* value);
int yaml_emit_int_field(yaml_emitter_t *emitter, yaml_event_t *event, const char* field, int value);
int yaml_emit_bool_field(yaml_emitter_t *emitter, yaml_event_t *event, const char* field, int value);
int yaml_parse_bool_scalar(yaml_event_t *event, bool* value, char* file, int line);
int yaml_parse_string_scalar(yaml_event_t *event, char** value);
long int yaml_parse_long_int_scalar(yaml_event_t *event, long int* value, char* file, int line);
int yaml_dump_block(yaml_parser_t *parser, yaml_event_t *event);

#endif //MOSQUITTO_UTIL_H
