//
// Created by Akos Vandra on 2023-01-20.
//
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "yaml_help.h"
#include "yaml.h"
#include <string.h>
#include "mosquitto.h"
#include "mosquitto_broker.h"


void indent(int level)
{
    int i;
    for (i = 0; i < level; i++) {
        printf("%s", "  ");
    }
}

char* yaml_event_type_name(yaml_event_type_t t) {
    switch(t) {
        case YAML_NO_EVENT: return "no-event";
        case YAML_STREAM_START_EVENT: return "stream-start-event";
        case YAML_STREAM_END_EVENT: return "stream-end-event";
        case YAML_DOCUMENT_START_EVENT: return "document-start-event";
        case YAML_DOCUMENT_END_EVENT: return "document-end-event";
        case YAML_ALIAS_EVENT: return "alias-event";
        case YAML_SCALAR_EVENT: return "scalar-event";
        case YAML_SEQUENCE_START_EVENT: return "sequence-start-event";
        case YAML_SEQUENCE_END_EVENT: return "sequence-end-event";
        case YAML_MAPPING_START_EVENT: return "mapping-start-event";
        case YAML_MAPPING_END_EVENT: return "mapping-end-event";
    }

    return "invalid value!";
}

void yaml_print_event(yaml_event_t *event, int level)
{
    switch (event->type) {
        case YAML_NO_EVENT:
            indent(level);
            printf("no-event (%d)\n", event->type);
            break;
        case YAML_STREAM_START_EVENT:
            indent(level++);
            printf("stream-start-event (%d)\n", event->type);
            break;
        case YAML_STREAM_END_EVENT:
            indent(--level);
            printf("stream-end-event (%d)\n", event->type);
            break;
        case YAML_DOCUMENT_START_EVENT:
            indent(level++);
            printf("document-start-event (%d)\n", event->type);
            break;
        case YAML_DOCUMENT_END_EVENT:
            indent(--level);
            printf("document-end-event (%d)\n", event->type);
            break;
        case YAML_ALIAS_EVENT:
            indent(level);
            printf("alias-event (%d)\n", event->type);
            break;
        case YAML_SCALAR_EVENT:
            indent(level);
            printf("scalar-event (%d) = {value=\"%s\", length=%d}\n",
                   event->type,
                   (char*)event->data.scalar.value,
                   (int)event->data.scalar.length);
            break;
        case YAML_SEQUENCE_START_EVENT:
            indent(level++);
            printf("sequence-start-event (%d)\n", event->type);
            break;
        case YAML_SEQUENCE_END_EVENT:
            indent(--level);
            printf("sequence-end-event (%d)\n", event->type);
            break;
        case YAML_MAPPING_START_EVENT:
            indent(level++);
            printf("mapping-start-event (%d)\n", event->type);
            break;
        case YAML_MAPPING_END_EVENT:
            indent(--level);
            printf("mapping-end-event (%d)\n", event->type);
            break;
    }
    if (level < 0) {
        printf("indentation underflow!\n");
        level = 0;
    }
}

int yaml_parse_string_scalar(yaml_event_t *event, char** value) {
    int ret = 1;

    PARSER_EXPECT_EVENT_TYPE(event, YAML_SCALAR_EVENT, { ret = 0; });

    *value = mosquitto_strdup((char*)event->data.scalar.value);

    yaml_event_delete(event);
    return ret;
}

long int yaml_parse_long_int_scalar(yaml_event_t *event, long int* value, char* file, int line) {
    int ret = 1;
    char* endptr;

    PARSER_EXPECT_EVENT_TYPE(event, YAML_SCALAR_EVENT, { ret = 0; });

    *value = strtol((char*)event->data.scalar.value, &endptr, 10);

    if (strlen(endptr) > 0) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error parsing Dynamic security plugin config. Expected integer value, but got %s on line %d:%d at %s:%d", event->data.scalar.value, event->start_mark.line, event->start_mark.column, file, line);
        ret = 0;
    }

    yaml_event_delete(event);
    return ret;
}


int yaml_parse_bool_scalar(yaml_event_t *event, bool* value, char* file, int line) {
    int ret = 1;

    PARSER_EXPECT_EVENT_TYPE(event, YAML_SCALAR_EVENT, { ret = 0; });

    if (strcmp((char*)event->data.scalar.value, "true") == 0) {
        *value = true;
    } else if (strcmp((char*)event->data.scalar.value, "false") == 0) {
        *value = false;
    } else {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error parsing Dynamic security plugin config. Expected boolean value (true,false), but got %s on line %d:%d at %s:%d", event->data.scalar.value, event->type, event->start_mark.line, event->start_mark.column, file, line);              \
        ret = 0;
    }

    yaml_event_delete(event);
    return ret;
}



int yaml_emit_string_field(yaml_emitter_t *emitter, yaml_event_t *event, const char* field, const char* value) {
    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)field, (int)strlen(field), 1, 1, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 0;

    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)value, (int)strlen(value), 1, 1, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 0;

    return 1;
}

int yaml_emit_int_field(yaml_emitter_t *emitter, yaml_event_t *event, const char* field, int value) {
    char buf[33] = { '\0' };
    snprintf(buf, 32, "%d", value);

    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)field, (int)strlen(field), 1, 1, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 0;

    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_INT_TAG,
                                 (yaml_char_t *)buf, (int)strlen(buf), 1, 1, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 0;

    return 1;
}

int yaml_emit_bool_field(yaml_emitter_t *emitter, yaml_event_t *event, const char* field, int value) {
    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)field, (int)strlen(field), 1, 1, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 0;

    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_BOOL_TAG,
                                 (yaml_char_t *)(value ? "true" : "false"), (int)strlen(value ? "true" : "false"), 1, 1, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 0;

    return 1;
}

int yaml_dump_block(yaml_parser_t *parser, yaml_event_t *event) {
    int nest = 0;

    do {
        yaml_print_event(event, nest);

        if (event->type == YAML_MAPPING_START_EVENT || event->type == YAML_SEQUENCE_START_EVENT) nest++;
        if (event->type == YAML_MAPPING_END_EVENT || event->type == YAML_SEQUENCE_END_EVENT) nest--;

        if (nest == 0) break;
        if (!yaml_parser_parse(parser, event)) return 0;
    } while (nest > 0);

    return 1;
}
