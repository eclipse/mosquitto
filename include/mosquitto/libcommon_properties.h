/*
Copyright (c) 2010-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#ifndef MOSQUITTO_LIBCOMMON_PROPERTIES_H
#define MOSQUITTO_LIBCOMMON_PROPERTIES_H

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 *
 * Section: Properties
 *
 * =============================================================================
 */


/*
 * Function: mosquitto_property_add_byte
 *
 * Add a new byte property to a property list.
 *
 * If *proplist == NULL, a new list will be created, otherwise the new property
 * will be appended to the list.
 *
 * Parameters:
 *	proplist - pointer to mosquitto_property pointer, the list of properties
 *	identifier - property identifier (e.g. MQTT_PROP_PAYLOAD_FORMAT_INDICATOR)
 *	value - integer value for the new property
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL - if identifier is invalid, or if proplist is NULL
 *	MOSQ_ERR_NOMEM - on out of memory
 *
 * Example:
 * > mosquitto_property *proplist = NULL;
 * > mosquitto_property_add_byte(&proplist, MQTT_PROP_PAYLOAD_FORMAT_IDENTIFIER, 1);
 */
libmosqcommon_EXPORT int mosquitto_property_add_byte(mosquitto_property **proplist, int identifier, uint8_t value);

/*
 * Function: mosquitto_property_add_int16
 *
 * Add a new int16 property to a property list.
 *
 * If *proplist == NULL, a new list will be created, otherwise the new property
 * will be appended to the list.
 *
 * Parameters:
 *	proplist - pointer to mosquitto_property pointer, the list of properties
 *	identifier - property identifier (e.g. MQTT_PROP_RECEIVE_MAXIMUM)
 *	value - integer value for the new property
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL - if identifier is invalid, or if proplist is NULL
 *	MOSQ_ERR_NOMEM - on out of memory
 *
 * Example:
 * > mosquitto_property *proplist = NULL;
 * > mosquitto_property_add_int16(&proplist, MQTT_PROP_RECEIVE_MAXIMUM, 1000);
 */
libmosqcommon_EXPORT int mosquitto_property_add_int16(mosquitto_property **proplist, int identifier, uint16_t value);

/*
 * Function: mosquitto_property_add_int32
 *
 * Add a new int32 property to a property list.
 *
 * If *proplist == NULL, a new list will be created, otherwise the new property
 * will be appended to the list.
 *
 * Parameters:
 *	proplist - pointer to mosquitto_property pointer, the list of properties
 *	identifier - property identifier (e.g. MQTT_PROP_MESSAGE_EXPIRY_INTERVAL)
 *	value - integer value for the new property
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL - if identifier is invalid, or if proplist is NULL
 *	MOSQ_ERR_NOMEM - on out of memory
 *
 * Example:
 * > mosquitto_property *proplist = NULL;
 * > mosquitto_property_add_int32(&proplist, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 86400);
 */
libmosqcommon_EXPORT int mosquitto_property_add_int32(mosquitto_property **proplist, int identifier, uint32_t value);

/*
 * Function: mosquitto_property_add_varint
 *
 * Add a new varint property to a property list.
 *
 * If *proplist == NULL, a new list will be created, otherwise the new property
 * will be appended to the list.
 *
 * Parameters:
 *	proplist - pointer to mosquitto_property pointer, the list of properties
 *	identifier - property identifier (e.g. MQTT_PROP_SUBSCRIPTION_IDENTIFIER)
 *	value - integer value for the new property
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL - if identifier is invalid, or if proplist is NULL
 *	MOSQ_ERR_NOMEM - on out of memory
 *
 * Example:
 * > mosquitto_property *proplist = NULL;
 * > mosquitto_property_add_varint(&proplist, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 1);
 */
libmosqcommon_EXPORT int mosquitto_property_add_varint(mosquitto_property **proplist, int identifier, uint32_t value);

/*
 * Function: mosquitto_property_add_binary
 *
 * Add a new binary property to a property list.
 *
 * If *proplist == NULL, a new list will be created, otherwise the new property
 * will be appended to the list.
 *
 * Parameters:
 *	proplist - pointer to mosquitto_property pointer, the list of properties
 *	identifier - property identifier (e.g. MQTT_PROP_PAYLOAD_FORMAT_INDICATOR)
 *	value - pointer to the property data
 *	len - length of property data in bytes
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL - if identifier is invalid, or if proplist is NULL
 *	MOSQ_ERR_NOMEM - on out of memory
 *
 * Example:
 * > mosquitto_property *proplist = NULL;
 * > mosquitto_property_add_binary(&proplist, MQTT_PROP_AUTHENTICATION_DATA, auth_data, auth_data_len);
 */
libmosqcommon_EXPORT int mosquitto_property_add_binary(mosquitto_property **proplist, int identifier, const void *value, uint16_t len);

/*
 * Function: mosquitto_property_add_string
 *
 * Add a new string property to a property list.
 *
 * If *proplist == NULL, a new list will be created, otherwise the new property
 * will be appended to the list.
 *
 * Parameters:
 *	proplist - pointer to mosquitto_property pointer, the list of properties
 *	identifier - property identifier (e.g. MQTT_PROP_CONTENT_TYPE)
 *	value - string value for the new property, must be UTF-8 and zero terminated
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL - if identifier is invalid, if value is NULL, or if proplist is NULL
 *	MOSQ_ERR_NOMEM - on out of memory
 *	MOSQ_ERR_MALFORMED_UTF8 - value is not valid UTF-8.
 *
 * Example:
 * > mosquitto_property *proplist = NULL;
 * > mosquitto_property_add_string(&proplist, MQTT_PROP_CONTENT_TYPE, "application/json");
 */
libmosqcommon_EXPORT int mosquitto_property_add_string(mosquitto_property **proplist, int identifier, const char *value);

/*
 * Function: mosquitto_property_add_string_pair
 *
 * Add a new string pair property to a property list.
 *
 * If *proplist == NULL, a new list will be created, otherwise the new property
 * will be appended to the list.
 *
 * Parameters:
 *	proplist - pointer to mosquitto_property pointer, the list of properties
 *	identifier - property identifier (e.g. MQTT_PROP_USER_PROPERTY)
 *	name - string name for the new property, must be UTF-8 and zero terminated
 *	value - string value for the new property, must be UTF-8 and zero terminated
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL - if identifier is invalid, if name or value is NULL, or if proplist is NULL
 *	MOSQ_ERR_NOMEM - on out of memory
 *	MOSQ_ERR_MALFORMED_UTF8 - if name or value are not valid UTF-8.
 *
 * Example:
 * > mosquitto_property *proplist = NULL;
 * > mosquitto_property_add_string_pair(&proplist, MQTT_PROP_USER_PROPERTY, "client", "mosquitto_pub");
 */
libmosqcommon_EXPORT int mosquitto_property_add_string_pair(mosquitto_property **proplist, int identifier, const char *name, const char *value);


/*
 * Function: mosquitto_property_remove
 *
 * Remove a property from a property list. The property will not be freed.
 *
 * Parameters:
 *	proplist - pointer to mosquitto_property pointer, the list of properties
 *	property - pointer to the property to remove
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL - if proplist is NULL or property is NULL
 *	MOSQ_ERR_NOT_FOUND - if the property was not found
 */
libmosqcommon_EXPORT int mosquitto_property_remove(mosquitto_property **proplist, const mosquitto_property *property);


/*
 * Function: mosquitto_property_identifier
 *
 * Return the property identifier for a single property.
 *
 * Parameters:
 *	property - pointer to a valid mosquitto_property pointer.
 *
 * Returns:
 *  A valid property identifier on success
 *  0 - on error
 */
libmosqcommon_EXPORT int mosquitto_property_identifier(const mosquitto_property *property);


/*
 * Function: mosquitto_property_next
 *
 * Return the next property in a property list. Use to iterate over a property
 * list, e.g.:
 *
 * (start code)
 * for(prop = proplist; prop != NULL; prop = mosquitto_property_next(prop)){
 * 	if(mosquitto_property_identifier(prop) == MQTT_PROP_CONTENT_TYPE){
 * 		...
 * 	}
 * }
 * (end)
 *
 * Parameters:
 *	proplist - pointer to mosquitto_property pointer, the list of properties
 *
 * Returns:
 *	Pointer to the next item in the list
 *	NULL, if proplist is NULL, or if there are no more items in the list.
 */
libmosqcommon_EXPORT mosquitto_property *mosquitto_property_next(const mosquitto_property *proplist);


/*
 * Function: mosquitto_property_read_byte
 *
 * Attempt to read a byte property matching an identifier, from a property list
 * or single property. This function can search for multiple entries of the
 * same identifier by using the returned value and skip_first. Note however
 * that it is forbidden for most properties to be duplicated.
 *
 * If the property is not found, *value will not be modified, so it is safe to
 * pass a variable with a default value to be potentially overwritten:
 *
 * (start code)
 * uint16_t keepalive = 60; // default value
 * // Get value from property list, or keep default if not found.
 * mosquitto_property_read_int16(proplist, MQTT_PROP_SERVER_KEEP_ALIVE, &keepalive, false);
 * (end)
 *
 * Parameters:
 *	proplist - mosquitto_property pointer, the list of properties or single property
 *	identifier - property identifier (e.g. MQTT_PROP_PAYLOAD_FORMAT_INDICATOR)
 *	value - pointer to store the value, or NULL if the value is not required.
 *	skip_first - boolean that indicates whether the first item in the list
 *	             should be ignored or not. Should usually be set to false.
 *
 * Returns:
 *	A valid property pointer if the property is found
 *	NULL, if the property is not found, or proplist is NULL.
 *
 * Example:
 * (start code)
 *	// proplist is obtained from a callback
 *	mosquitto_property *prop;
 *	prop = mosquitto_property_read_byte(proplist, identifier, &value, false);
 *	while(prop){
 *		printf("value: %s\n", value);
 *		prop = mosquitto_property_read_byte(prop, identifier, &value);
 *	}
 * (end)
 */
libmosqcommon_EXPORT const mosquitto_property *mosquitto_property_read_byte(
		const mosquitto_property *proplist,
		int identifier,
		uint8_t *value,
		bool skip_first);

/*
 * Function: mosquitto_property_read_int16
 *
 * Read an int16 property value from a property.
 *
 * Parameters:
 *	property - property to read
 *	identifier - property identifier (e.g. MQTT_PROP_PAYLOAD_FORMAT_INDICATOR)
 *	value - pointer to store the value, or NULL if the value is not required.
 *	skip_first - boolean that indicates whether the first item in the list
 *	             should be ignored or not. Should usually be set to false.
 *
 * Returns:
 *	A valid property pointer if the property is found
 *	NULL, if the property is not found, or proplist is NULL.
 *
 * Example:
 *	See <mosquitto_property_read_byte>
 */
libmosqcommon_EXPORT const mosquitto_property *mosquitto_property_read_int16(
		const mosquitto_property *proplist,
		int identifier,
		uint16_t *value,
		bool skip_first);

/*
 * Function: mosquitto_property_read_int32
 *
 * Read an int32 property value from a property.
 *
 * Parameters:
 *	property - pointer to mosquitto_property pointer, the list of properties
 *	identifier - property identifier (e.g. MQTT_PROP_PAYLOAD_FORMAT_INDICATOR)
 *	value - pointer to store the value, or NULL if the value is not required.
 *	skip_first - boolean that indicates whether the first item in the list
 *	             should be ignored or not. Should usually be set to false.
 *
 * Returns:
 *	A valid property pointer if the property is found
 *	NULL, if the property is not found, or proplist is NULL.
 *
 * Example:
 *	See <mosquitto_property_read_byte>
 */
libmosqcommon_EXPORT const mosquitto_property *mosquitto_property_read_int32(
		const mosquitto_property *proplist,
		int identifier,
		uint32_t *value,
		bool skip_first);

/*
 * Function: mosquitto_property_read_varint
 *
 * Read a varint property value from a property.
 *
 * Parameters:
 *	property - property to read
 *	identifier - property identifier (e.g. MQTT_PROP_PAYLOAD_FORMAT_INDICATOR)
 *	value - pointer to store the value, or NULL if the value is not required.
 *	skip_first - boolean that indicates whether the first item in the list
 *	             should be ignored or not. Should usually be set to false.
 *
 * Returns:
 *	A valid property pointer if the property is found
 *	NULL, if the property is not found, or proplist is NULL.
 *
 * Example:
 *	See <mosquitto_property_read_byte>
 */
libmosqcommon_EXPORT const mosquitto_property *mosquitto_property_read_varint(
		const mosquitto_property *proplist,
		int identifier,
		uint32_t *value,
		bool skip_first);

/*
 * Function: mosquitto_property_read_binary
 *
 * Read a binary property value from a property.
 *
 * On success, value must be free()'d by the application.
 *
 * Parameters:
 *	property - property to read
 *	identifier - property identifier (e.g. MQTT_PROP_PAYLOAD_FORMAT_INDICATOR)
 *	value - pointer to store the value, or NULL if the value is not required.
 *	        Will be set to NULL if the value has zero length.
 *	skip_first - boolean that indicates whether the first item in the list
 *	             should be ignored or not. Should usually be set to false.
 *
 * Returns:
 *	A valid property pointer if the property is found
 *	NULL, if the property is not found, or proplist is NULL, or if an out of memory condition occurred.
 *
 * Example:
 *	See <mosquitto_property_read_byte>
 */
libmosqcommon_EXPORT const mosquitto_property *mosquitto_property_read_binary(
		const mosquitto_property *proplist,
		int identifier,
		void **value,
		uint16_t *len,
		bool skip_first);

/*
 * Function: mosquitto_property_read_string
 *
 * Read a string property value from a property.
 *
 * On success, value must be free()'d by the application.
 *
 * Parameters:
 *	property - property to read
 *	identifier - property identifier (e.g. MQTT_PROP_PAYLOAD_FORMAT_INDICATOR)
 *	value - pointer to char*, for the property data to be stored in, or NULL if
 *	        the value is not required.
 *	        Will be set to NULL if the value has zero length.
 *	skip_first - boolean that indicates whether the first item in the list
 *	             should be ignored or not. Should usually be set to false.
 *
 * Returns:
 *	A valid property pointer if the property is found
 *	NULL, if the property is not found, or proplist is NULL, or if an out of memory condition occurred.
 *
 * Example:
 *	See <mosquitto_property_read_byte>
 */
libmosqcommon_EXPORT const mosquitto_property *mosquitto_property_read_string(
		const mosquitto_property *proplist,
		int identifier,
		char **value,
		bool skip_first);

/*
 * Function: mosquitto_property_read_string_pair
 *
 * Read a string pair property value pair from a property.
 *
 * On success, name and value must be free()'d by the application.
 *
 * Parameters:
 *	property - property to read
 *	identifier - property identifier (e.g. MQTT_PROP_PAYLOAD_FORMAT_INDICATOR)
 *	name - pointer to char* for the name property data to be stored in, or NULL
 *	       if the name is not required.
 *	       Will be set to NULL if the name has zero length.
 *	value - pointer to char*, for the property data to be stored in, or NULL if
 *	        the value is not required.
 *	        Will be set to NULL if the value has zero length.
 *	skip_first - boolean that indicates whether the first item in the list
 *	             should be ignored or not. Should usually be set to false.
 *
 * Returns:
 *	A valid property pointer if the property is found
 *	NULL, if the property is not found, or proplist is NULL, or if an out of memory condition occurred.
 *
 * Example:
 *	See <mosquitto_property_read_byte>
 */
libmosqcommon_EXPORT const mosquitto_property *mosquitto_property_read_string_pair(
		const mosquitto_property *proplist,
		int identifier,
		char **name,
		char **value,
		bool skip_first);

/*
 * Function: mosquitto_property_type
 *
 * Return the property type for a single property.
 *
 * Parameters:
 *	property - pointer to a valid mosquitto_property pointer.
 *
 * Returns:
 *  A valid property type on success
 *  0 - on error
 */
libmosqcommon_EXPORT int mosquitto_property_type(const mosquitto_property *property);


/*
 * Function: mosquitto_property_byte_value
 *
 * Return the property value for a byte type property.
 *
 * Parameters:
 *	property - pointer to a valid mosquitto_property pointer.
 *
 * Returns:
 *  Byte value on success
 *  0 - on error (property is NULL, or not a byte)
 */
libmosqcommon_EXPORT uint8_t mosquitto_property_byte_value(const mosquitto_property *property);


/*
 * Function: mosquitto_property_int16_value
 *
 * Return the property value for an int16 type property.
 *
 * Parameters:
 *	property - pointer to a valid mosquitto_property pointer.
 *
 * Returns:
 *  Int16 value on success
 *  0 - on error (property is NULL, or not a int16)
 */
libmosqcommon_EXPORT uint16_t mosquitto_property_int16_value(const mosquitto_property *property);


/*
 * Function: mosquitto_property_int32_value
 *
 * Return the property value for an int32 type property.
 *
 * Parameters:
 *	property - pointer to a valid mosquitto_property pointer.
 *
 * Returns:
 *  Int32 value on success
 *  0 - on error (property is NULL, or not a int32)
 */
libmosqcommon_EXPORT uint32_t mosquitto_property_int32_value(const mosquitto_property *property);


/*
 * Function: mosquitto_property_varint_value
 *
 * Return the property value for a varint type property.
 *
 * Parameters:
 *	property - pointer to a valid mosquitto_property pointer.
 *
 * Returns:
 *  Varint value on success
 *  0 - on error (property is NULL, or not a varint)
 */
libmosqcommon_EXPORT uint32_t mosquitto_property_varint_value(const mosquitto_property *property);


/*
 * Function: mosquitto_property_binary_value
 *
 * Return the property value for a binary type property.
 *
 * Parameters:
 *	property - pointer to a valid mosquitto_property pointer.
 *
 * Returns:
 *  Binary value on success
 *  NULL - on error (property is NULL, or not a binary)
 */
libmosqcommon_EXPORT const void *mosquitto_property_binary_value(const mosquitto_property *property);


/*
 * Function: mosquitto_property_byte_value_length
 *
 * Return the property value for a byte type property.
 *
 * Parameters:
 *	property - pointer to a valid mosquitto_property pointer.
 *
 * Returns:
 *  Binary value length on success
 *  0 - on error (property is NULL, or not a binary)
 */
libmosqcommon_EXPORT uint16_t mosquitto_property_binary_value_length(const mosquitto_property *property);


/*
 * Function: mosquitto_property_string_value
 *
 * Return the property value for a string or string pair type property.
 *
 * Parameters:
 *	property - pointer to a valid mosquitto_property pointer.
 *
 * Returns:
 *  String value on success
 *  NULL - on error (property is NULL, or not a string or string pair)
 */
libmosqcommon_EXPORT const char *mosquitto_property_string_value(const mosquitto_property *property);


/*
 * Function: mosquitto_property_string_value_length
 *
 * Return the length of the property value for a string or string pair type property.
 *
 * Parameters:
 *	property - pointer to a valid mosquitto_property pointer.
 *
 * Returns:
 *  Value length on success
 *  0 - on error (property is NULL, or not a string or string pair)
 */
libmosqcommon_EXPORT uint16_t mosquitto_property_string_value_length(const mosquitto_property *property);


/*
 * Function: mosquitto_property_string_value
 *
 * Return the property name for a string pair type property.
 *
 * Parameters:
 *	property - pointer to a valid mosquitto_property pointer.
 *
 * Returns:
 *  String name on success
 *  NULL - on error (property is NULL, or not a string pair)
 */
libmosqcommon_EXPORT const char *mosquitto_property_string_name(const mosquitto_property *property);


/*
 * Function: mosquitto_property_string_name_length
 *
 * Return the property name length for a string pair type property.
 *
 * Parameters:
 *	property - pointer to a valid mosquitto_property pointer.
 *
 * Returns:
 *  Name length on success
 *  0 - on error (property is NULL, or not a string pair)
 */
libmosqcommon_EXPORT uint16_t mosquitto_property_string_name_length(const mosquitto_property *property);


/*
 * Function: mosquitto_property_free_all
 *
 * Free all properties from a list of properties. Frees the list and sets *properties to NULL.
 *
 * Parameters:
 *   properties - list of properties to free
 *
 * Example:
 * > mosquitto_properties *properties = NULL;
 * > // Add properties
 * > mosquitto_property_free_all(&properties);
 */
libmosqcommon_EXPORT void mosquitto_property_free_all(mosquitto_property **properties);

/*
 * Function: mosquitto_property_copy_all
 *
 * Parameters:
 *    dest - pointer for new property list
 *    src - property list
 *
 * Returns:
 *    MOSQ_ERR_SUCCESS - on successful copy
 *    MOSQ_ERR_INVAL - if dest is NULL
 *    MOSQ_ERR_NOMEM - on out of memory (dest will be set to NULL)
 */
libmosqcommon_EXPORT int mosquitto_property_copy_all(mosquitto_property **dest, const mosquitto_property *src);

/*
 * Function: mosquitto_property_check_command
 *
 * Check whether a property identifier is valid for the given command.
 *
 * Parameters:
 *   command - MQTT command (e.g. CMD_CONNECT)
 *   identifier - MQTT property (e.g. MQTT_PROP_USER_PROPERTY)
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - if the identifier is valid for command
 *   MOSQ_ERR_PROTOCOL - if the identifier is not valid for use with command.
 */
libmosqcommon_EXPORT int mosquitto_property_check_command(int command, int identifier);


/*
 * Function: mosquitto_property_check_all
 *
 * Check whether a list of properties are valid for a particular command,
 * whether there are duplicates, and whether the values are valid where
 * possible.
 *
 * Note that this function is used internally in the library whenever
 * properties are passed to it, so in basic use this is not needed, but should
 * be helpful to check property lists *before* the point of using them.
 *
 * Parameters:
 *	command - MQTT command (e.g. CMD_CONNECT)
 *	properties - list of MQTT properties to check.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - if all properties are valid
 *	MOSQ_ERR_DUPLICATE_PROPERTY - if a property is duplicated where it is forbidden.
 *	MOSQ_ERR_PROTOCOL - if any property is invalid
 */
libmosqcommon_EXPORT int mosquitto_property_check_all(int command, const mosquitto_property *properties);

/*
 * Function: mosquitto_property_identifier_to_string
 *
 * Return the property name as a string for a property identifier.
 * The property name is as defined in the MQTT specification, with - as a
 * separator, for example: payload-format-indicator.
 *
 * Parameters:
 *	identifier - valid MQTT property identifier integer
 *
 * Returns:
 *  A const string to the property name on success
 *  NULL on failure
 */
libmosqcommon_EXPORT const char *mosquitto_property_identifier_to_string(int identifier);


/* Function: mosquitto_string_to_property_info
 *
 * Parse a property name string and convert to a property identifier and data type.
 * The property name is as defined in the MQTT specification, with - as a
 * separator, for example: payload-format-indicator.
 *
 * Parameters:
 *	propname - the string to parse
 *	identifier - pointer to an int to receive the property identifier
 *	type - pointer to an int to receive the property type
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL - if the string does not match a property
 *
 * Example:
 * (start code)
 *	mosquitto_string_to_property_info("response-topic", &id, &type);
 *	// id == MQTT_PROP_RESPONSE_TOPIC
 *	// type == MQTT_PROP_TYPE_STRING
 * (end)
 */
libmosqcommon_EXPORT int mosquitto_string_to_property_info(const char *propname, int *identifier, int *type);


libmosqcommon_EXPORT void mosquitto_property_free(mosquitto_property **property);
libmosqcommon_EXPORT unsigned int mosquitto_property_get_length(const mosquitto_property *property);
libmosqcommon_EXPORT unsigned int mosquitto_property_get_length_all(const mosquitto_property *property);
libmosqcommon_EXPORT unsigned int mosquitto_property_get_remaining_length(const mosquitto_property* props);
libmosqcommon_EXPORT unsigned int mosquitto_varint_bytes(uint32_t word);

#ifdef __cplusplus
}
#endif

#endif
