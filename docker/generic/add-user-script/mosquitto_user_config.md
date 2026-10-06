# Adding User Without Restart the mosquitto docker container

## On host server, below command must be executed. 
```bash
./mosquitto_add_user.sh username="USER_NAME_HERE" password="PASSWORD_HERE" acl="ACL_DEFINITION_HERE"
```
## Explanation of parameters

- **_username_:**  MQTT Username definition.
- **_password_:**  MQTT password of user.  
- **_acl_:** (optional) If `acl_file /acl` definition exist on mosquitto.conf, "acl" definition can be added by this parameter. For detail "acl" definitions http://www.steves-internet-guide.com/topic-restriction-mosquitto-configuration/
