// Fuzz driver for:
//   int dynsec_roles__process_add_acl(struct dynsec__data * data, struct mosquitto_control_cmd * cmd);
// Uses the real target implementation from the project (no fake dynsec_roles__process_add_acl stub).
// Fixed to keep minimal stubs only for symbols that are genuinely missing at link time.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <string>
#include <algorithm>

extern "C" {
#include "/src/cJSON/cJSON.h"
#include "/src/mosquitto/plugins/dynamic-security/dynamic_security.h"
#include "/src/mosquitto/include/mosquitto/broker_control.h"
}

// Provide lightweight stubs for symbols that may not be available at link time
// (This avoids undefined reference linker errors during building of the fuzz targets).
extern "C" {

// Note: Do NOT provide a fake dynsec_roles__process_add_acl implementation here.
// The real implementation from the project will be used (from plugins/dynamic-security/roles.c).
// We keep only other small stubs that the build references.

int fuzz_packet_read_init(struct mosquitto *context)
{
    (void)context;
    return 0;
}

void fuzz_packet_read_cleanup(struct mosquitto *context)
{
    (void)context;
}

} // extern "C"

// Helper: map arbitrary bytes to a printable, UTF-8-safe string (a..z)
static std::string make_printable_string(const uint8_t *data, size_t size, size_t max_len = 64)
{
    std::string out;
    if(!data || size == 0) return out;
    size_t use = std::min(size, max_len);
    out.resize(use);
    for(size_t i = 0; i < use; i++){
        // map to lowercase letters
        out[i] = char('a' + (data[i] % 26));
    }
    return out;
}

static struct dynsec__role * create_role_with_name(const char *name)
{
    if(!name) return nullptr;
    size_t nlen = strlen(name);
    // allocate space for struct + rolename flexible array + null
    size_t alloc_sz = sizeof(struct dynsec__role) + nlen + 1;
    struct dynsec__role *role = (struct dynsec__role *)malloc(alloc_sz);
    if(!role) return nullptr;
    // zero everything
    memset(role, 0, alloc_sz);
    // copy the rolename into the flexible array
    memcpy(role->rolename, name, nlen+1);
    return role;
}

// Free any ACLs attached to a role (they are allocated with mosquitto_calloc / freed with mosquitto_free)
static void free_role_acls(struct dynsec__role *role)
{
    if(!role) return;

    struct dynsec__acl *acl, *tmp;

    // publish_c_send
    HASH_ITER(hh, role->acls.publish_c_send, acl, tmp){
        HASH_DELETE(hh, role->acls.publish_c_send, acl);
        mosquitto_free(acl);
    }
    // publish_c_recv
    HASH_ITER(hh, role->acls.publish_c_recv, acl, tmp){
        HASH_DELETE(hh, role->acls.publish_c_recv, acl);
        mosquitto_free(acl);
    }
    // subscribe_literal
    HASH_ITER(hh, role->acls.subscribe_literal, acl, tmp){
        HASH_DELETE(hh, role->acls.subscribe_literal, acl);
        mosquitto_free(acl);
    }
    // subscribe_pattern
    HASH_ITER(hh, role->acls.subscribe_pattern, acl, tmp){
        HASH_DELETE(hh, role->acls.subscribe_pattern, acl);
        mosquitto_free(acl);
    }
    // unsubscribe_literal
    HASH_ITER(hh, role->acls.unsubscribe_literal, acl, tmp){
        HASH_DELETE(hh, role->acls.unsubscribe_literal, acl);
        mosquitto_free(acl);
    }
    // unsubscribe_pattern
    HASH_ITER(hh, role->acls.unsubscribe_pattern, acl, tmp){
        HASH_DELETE(hh, role->acls.unsubscribe_pattern, acl);
        mosquitto_free(acl);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(Data == nullptr || Size == 0) return 0;

    // Attempt to parse the input as JSON command
    cJSON *j_command = nullptr;
    // cJSON_Parse expects a NUL-terminated string. Create a temporary buffer.
    // Limit to a reasonable size to avoid huge allocations.
    size_t parse_len = std::min(Size, (size_t)65536);
    // If input includes zeros, cJSON_Parse will stop early; still acceptable.
    char *tmpbuf = (char *)malloc(parse_len + 1);
    if(!tmpbuf) return 0;
    memcpy(tmpbuf, Data, parse_len);
    tmpbuf[parse_len] = '\0';
    j_command = cJSON_Parse(tmpbuf);
    free(tmpbuf);

    // If parsing failed, synthesize a basic command using derived printable strings.
    std::string rolename;
    std::string topic;
    if(j_command == nullptr){
        j_command = cJSON_CreateObject();
        // derive rolename and topic from the input bytes
        rolename = make_printable_string(Data, Size, 24);
        topic = make_printable_string(Data + (Size/3), Size > (Size/3) ? (Size - Size/3) : 0, 48);
        if(rolename.empty()) rolename = "role";
        if(topic.empty()) topic = "a/topic";
        cJSON_AddStringToObject(j_command, "rolename", rolename.c_str());
        // choose a valid acltype so deeper codepaths are exercised
        cJSON_AddStringToObject(j_command, "acltype", ACL_TYPE_SUB_LITERAL);
        cJSON_AddStringToObject(j_command, "topic", topic.c_str());
        // optionally add priority/allow
        cJSON_AddNumberToObject(j_command, "priority", 10);
        cJSON_AddBoolToObject(j_command, "allow", true);
    }else{
        // If parsing succeeded, try to read rolename/topic; if missing, add defaults.
        cJSON *jr = cJSON_GetObjectItemCaseSensitive(j_command, "rolename");
        if(!jr || !cJSON_IsString(jr) || !jr->valuestring){
            rolename = make_printable_string(Data, Size, 24);
            if(rolename.empty()) rolename = "role";
            cJSON_AddStringToObject(j_command, "rolename", rolename.c_str());
        }else{
            rolename = jr->valuestring;
        }
        cJSON *jt = cJSON_GetObjectItemCaseSensitive(j_command, "topic");
        if(!jt || !cJSON_IsString(jt) || !jt->valuestring){
            topic = make_printable_string(Data + (Size/3), Size > (Size/3) ? (Size - Size/3) : 0, 48);
            if(topic.empty()) topic = "a/topic";
            cJSON_AddStringToObject(j_command, "topic", topic.c_str());
        }else{
            topic = jt->valuestring;
        }
        // ensure acltype exists
        cJSON *ja = cJSON_GetObjectItemCaseSensitive(j_command, "acltype");
        if(!ja || !cJSON_IsString(ja) || !ja->valuestring){
            cJSON_AddStringToObject(j_command, "acltype", ACL_TYPE_SUB_LITERAL);
        }
    }

    // Prepare j_responses array for replies
    cJSON *j_responses = cJSON_CreateArray();

    // Prepare a minimal mosquitto_control_cmd
    struct mosquitto_control_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.j_command = j_command;
    cmd.j_responses = j_responses;
    cmd.command_name = "addRoleACL";
    cmd.correlation_data = nullptr;
    cmd.client = nullptr; // keeping NULL is acceptable; code handles NULL client for id/username

    // Prepare dynsec__data and ensure a role exists with the requested rolename
    struct dynsec__data data;
    memset(&data, 0, sizeof(data));
    data.roles = nullptr;

    // Find the rolename string we added/detected
    const char *rolename_cstr = nullptr;
    cJSON *jr_check = cJSON_GetObjectItemCaseSensitive(j_command, "rolename");
    if(jr_check && cJSON_IsString(jr_check) && jr_check->valuestring){
        rolename_cstr = jr_check->valuestring;
    }else{
        // fallback
        rolename_cstr = "role";
    }

    // Create a role with that rolename and insert into the hash table
    struct dynsec__role *role = create_role_with_name(rolename_cstr);
    if(role){
        // Initialize role fields to safe defaults (already zeroed by create_role_with_name)
        // Insert into data.roles using uthash macro. Key is role->rolename with length strlen(...)
        HASH_ADD_KEYPTR(hh, data.roles, role->rolename, (unsigned)strlen(role->rolename), role);
    }

    // Call the real target function from the project.
    // This will examine j_command, find the role in data.roles, and attempt to add an ACL.
    (void)dynsec_roles__process_add_acl(&data, &cmd);

    // Cleanup: remove any ACLs attached to the role (they are allocated by the target with mosquitto_calloc)
    if(role){
        free_role_acls(role);

        // Remove role from the hash and free allocated memory for the role name struct
        HASH_DELETE(hh, data.roles, role);
        free(role);
    }

    // Free cJSON objects
    if(j_command) cJSON_Delete(j_command);
    if(j_responses) cJSON_Delete(j_responses);

    return 0;
}