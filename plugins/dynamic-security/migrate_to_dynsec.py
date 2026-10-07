#!/usr/bin/env python3
"""
Migration script to migrate from acl_file and password_file to the Dynamic Security Plugin.
"""

import json
import argparse
from pathlib import Path  # use Path to be able to handle Windows as well
from dataclasses import dataclass, asdict, field
from typing import Optional, Self


#
# Dynamic Security Plugin
#


@dataclass
class DynsecAclDefaultAccess:
    publishClientSend: bool = False
    publishClientReceive: bool = True
    subscribe: bool = False
    unsubscribe: bool = True


@dataclass
class DynSecAcl:
    acltype: str
    priority: int
    allow: bool
    topic: str


@dataclass
class DynSecRole:
    rolename: str = ""
    textname: str = ""
    textdescription: str = ""
    allowwildcardsubs: bool = True
    acls: list[DynSecAcl] = field(default_factory=list)

    @staticmethod
    def create_role_with_permissions(
        role_name: str,
        text_description: str,
        topic_pattern: str,
        permissions: list[str],
    ) -> Self:
        return DynSecRole(
            rolename=role_name,
            textdescription=text_description,
            acls=[
                DynSecAcl(permission, 0, True, topic_pattern)
                for permission in permissions
            ],
            allowwildcardsubs=True,
        )

    @staticmethod
    def create_role_with_full_permissions(
        role_name: str, text_description: str, topic_pattern: str
    ) -> Self:
        return DynSecRole.create_role_with_permissions(
            role_name=role_name,
            text_description=text_description,
            topic_pattern=topic_pattern,
            permissions=[
                "publishClientSend",
                "publishClientReceive",
                "subscribePattern",
                "unsubscribePattern",
            ],
        )


DYNSEC_DEFAULT_ROLES: list[DynSecRole] = [
    DynSecRole.create_role_with_full_permissions(
        role_name="client",
        text_description="Read/write access to the full application topic hierarchy.",
        topic_pattern="#",
    ),
    DynSecRole.create_role_with_full_permissions(
        role_name="broker-admin",
        text_description="Grants access to administer general broker configuration.",
        topic_pattern="$CONTROL/broker/#",
    ),
    DynSecRole.create_role_with_full_permissions(
        role_name="dynsec-admin",
        text_description="Grants access to administer clients/groups/roles.",
        topic_pattern="$CONTROL/dynamic-security/#",
    ),
    DynSecRole.create_role_with_full_permissions(
        role_name="inspect-admin",
        text_description="Grants access to administer inspect data.",
        topic_pattern="$CONTROL/cedalo/inspect/#",
    ),
    DynSecRole.create_role_with_full_permissions(
        role_name="super-admin",
        text_description="Grants access to administer all kind of broker controls",
        topic_pattern="$CONTROL/#",
    ),
    DynSecRole.create_role_with_permissions(
        role_name="sys-notify",
        text_description="Allow bridges to publish connection state messages.",
        topic_pattern=r"$SYS/broker/connection/%c/state",
        permissions=["publishClientSend"],
    ),
    DynSecRole.create_role_with_permissions(
        role_name="sys-observe",
        text_description="Observe the $SYS topic hierarchy.",
        topic_pattern="$SYS/#",
        permissions=["publishClientReceive", "subscribePattern"],
    ),
    DynSecRole.create_role_with_permissions(
        role_name="topic-observe",
        text_description="Read only access to the full application topic hierarchy.",
        topic_pattern="#",
        permissions=[
            "publishClientReceive",
            "subscribePattern",
            "unsubscribePattern",
        ],
    ),
]


@dataclass
class DynSecClient:
    username: str
    rolelist: list[dict[str, str]]
    password: Optional[str] = None
    salt: Optional[str] = None
    hash_algorithm_id: int = 7
    iterations: int = 1000
    encoded_password: Optional[int] = None
    textname: str = ""
    textdescription: str = ""
    # clientid omitted as it cannot be set for the user in the ACL file
    disabled: bool = False

    def asdict(self) -> dict:
        dynsec_client_as_dict = {
            "username": self.username,
            "roles": self.rolelist,
            "disabled": self.disabled,
        }

        if self.encoded_password is not None:
            dynsec_client_as_dict.update({"encoded_password": self.encoded_password})
        else:
            dynsec_client_as_dict.update(
                {
                    "password": self.password,
                    "salt": self.salt,
                    "iterations": self.iterations,
                }
            )

        if self.textname is not None:
            dynsec_client_as_dict.update({"textname": self.textname})

        if self.textdescription is not None:
            dynsec_client_as_dict.update({"textdescription": self.textdescription})

        return dynsec_client_as_dict


@dataclass
class DynSecGroup:
    groupname: str
    textname: str
    textdescription: str
    roles: list[DynSecRole]


DYNSEC_DEFAULT_ANON_GROUP = DynSecGroup(
    groupname="unauthenticated",
    textname="Unauthenticated group",
    textdescription="If unauthenticated access is allowed, this group can be used to define roles for clients that connect without a password.",
    roles=[],
)


@dataclass
class DynSecConfig:
    defaultACLAccess: DynsecAclDefaultAccess = field(
        default_factory=DynsecAclDefaultAccess
    )
    clients: list[DynSecClient] = field(default_factory=list)
    groups: list[DynSecGroup] = field(
        default_factory=lambda: [DYNSEC_DEFAULT_ANON_GROUP]
    )
    roles: list[DynSecRole] = field(default_factory=lambda: DYNSEC_DEFAULT_ROLES)
    anonymousGroup: str = "unauthenticated"

    def asdict(self) -> dict:
        return {
            "defaultACLAccess": asdict(self.defaultACLAccess),
            "clients": [client.asdict() for client in self.clients],
            "groups": [asdict(group) for group in self.groups],
            "roles": [asdict(role) for role in self.roles],
            "anonymousGroup": self.anonymousGroup,
        }


#
# ACL file
#

ACL_FILE_DYNSEC_MAP = {
    "read": [
        "subscribePattern",
    ],
    "write": ["publishClientSend"],
    "readwrite": [
        "subscribePattern",
        "publishClientSend",
    ],
    "deny": [
        "subscribePattern",
        "publishClientSend",
    ],
}


def is_parent_topic(parent_topic: str, topic: str, user: str = None) -> bool:
    if len(parent_topic) == 0 or len(topic) == 0:
        return False

    if (parent_topic.startswith("$") and not topic.startswith("$")) or (
        not parent_topic.startswith("$") and topic.startswith("$")
    ):
        return False

    tokens_sub_topic = parent_topic.split("/")
    tokens_topic = topic.split("/")

    if not "#" in parent_topic and len(tokens_sub_topic) != len(tokens_topic):
        return False

    for token_parent_topic, token_topic in zip(tokens_sub_topic, tokens_topic):
        if token_parent_topic in ("#", "+"):
            continue

        if token_parent_topic in (r"%c", r"%u"):
            if token_parent_topic == r"%u" and user is not None:
                token_parent_topic.replace(r"%u", user)
            else:
                continue

        if token_parent_topic != token_topic:
            return False

    return True


@dataclass
class AclFileConfig:
    global_acls: list[DynSecAcl] = field(default_factory=list)
    user_acls: dict[str, list[DynSecAcl]] = field(default_factory=dict)

    @staticmethod
    def topic_or_pattern_sanity_check(acl_file_line: str, tokens: list[str]) -> None:
        # At least topic/pattern keyword and the topic string must be provided
        if len(tokens) < 2:
            raise ValueError(
                f'Invalid topic/pattern definition: "{acl_file_line}" (Too few arguments)'
            )

        # Topic is missing
        if len(tokens) == 2 and tokens[1] in ACL_FILE_DYNSEC_MAP:
            raise ValueError(
                f'Invalid topic/pattern definition: "{acl_file_line}" (Topic missing)'
            )

        # Topic string contains at least one whitespace => access type is mandatory
        if len(tokens) > 3 and tokens[1] not in ACL_FILE_DYNSEC_MAP:
            raise ValueError(
                f'Invalid topic/pattern definition: "{acl_file_line}" (Access type missing)'
            )

    @staticmethod
    def parse_topic_or_pattern_acl(acl_file_line: str) -> list[DynSecAcl]:
        tokens = acl_file_line.strip().split(" ")

        # Raises in case of an invalid definition
        AclFileConfig.topic_or_pattern_sanity_check(acl_file_line, tokens)

        return [
            DynSecAcl(
                acltype=permission,
                priority=0 if len(tokens) == 2 or tokens[1] != "deny" else 1,
                allow=True if len(tokens) == 2 else tokens[1] != "deny",
                topic=tokens[1] if len(tokens) == 2 else " ".join(tokens[2:]),
            )
            for permission in (
                ACL_FILE_DYNSEC_MAP["readwrite"]
                if len(tokens) == 2
                else ACL_FILE_DYNSEC_MAP[tokens[1]]
            )
        ]

    @staticmethod
    def parse_acl_file(acl_file_path: Path) -> Self:
        acl_file_lines = acl_file_path.read_text(encoding="utf-8").splitlines()

        acl_file_config = AclFileConfig()
        current_user: str = None

        for line in acl_file_lines:
            if line.startswith("#"):
                continue

            if line.startswith("user"):
                current_user = line.replace("user ", "")
                if current_user not in acl_file_config.user_acls:
                    acl_file_config.user_acls[current_user] = []
                continue

            current_acls: list[DynSecAcl] = None
            if line.startswith("pattern") or line.startswith("topic"):
                current_acls = AclFileConfig.parse_topic_or_pattern_acl(line)

            if current_acls is not None:
                if not line.startswith("pattern") and current_user is not None:
                    acl_file_config.user_acls[current_user].extend(current_acls)
                else:
                    acl_file_config.global_acls.extend(current_acls)

        return acl_file_config


#
# Password file
#


@dataclass
class PasswordFile:
    username_password_map: dict[str, Optional[str]] = field(default_factory=dict)

    def __getitem__(self, username: str):
        return self.username_password_map[username]

    def __setitem__(self, username: str, pw_data: str):
        self.username_password_map[username] = pw_data

    @staticmethod
    def parse_password_file(pw_file_path: Path) -> Self:
        pw_file_lines = pw_file_path.read_text(encoding="utf-8").splitlines()

        pw_file = PasswordFile()
        for line in pw_file_lines:
            [username, password] = line.strip().split(":")
            pw_file[username] = password

        return pw_file


#
# Migration
#


def filter_used_deny_acls(acls: list[DynSecAcl], user: str = None) -> AclFileConfig:
    deny_acls = list(filter(lambda dynsec_acl: not dynsec_acl.allow, acls))
    allow_acls = list(filter(lambda dynsec_acl: dynsec_acl not in deny_acls, acls))
    final_acls = []

    for deny_acl in deny_acls:
        for allow_acl in allow_acls:
            if is_parent_topic(allow_acl.topic, deny_acl.topic, user):
                final_acls.append(deny_acl)
                break
        if deny_acl not in final_acls:
            print(f"WARNING: Removing unused 'deny' ACL: {deny_acl}")

    final_acls.extend(allow_acls)
    return final_acls


def migrate_to_dynsec(
    acl_file_config: AclFileConfig, pw_file: PasswordFile
) -> DynSecConfig:
    dynsec_config = DynSecConfig()

    for user in pw_file.username_password_map.keys():
        user_rolename = f"client-role-{user}"

        # ACL file
        user_acls = acl_file_config.user_acls.get(user)
        if user_acls is not None:
            user_acls_filtered = filter_used_deny_acls(
                acl_file_config.user_acls[user], user
            )
            dynsec_config.roles.append(
                DynSecRole(rolename=user_rolename, acls=user_acls_filtered)
            )

        new_client = DynSecClient(
            username=user,
            rolelist=[{"rolename": user_rolename}] if user_acls is not None else [],
        )

        # Password file
        user_password_details = pw_file[user]
        if user_password_details.startswith("$argon2id"):
            new_client.encoded_password = user_password_details
        else:
            # leading "$" creates an empty string on split and hash algo ID is unused
            #   -> omit first two elements from split
            [iterations_string, new_client.salt, new_client.password] = (
                user_password_details.split("$")[2:]
            )
            new_client.iterations = int(iterations_string)

        dynsec_config.clients.append(new_client)

    return dynsec_config


def migrate_mosquitto_conf(
    mosquitto_conf: str, dynsec_lib_path: Path, dynsec_config_path: Path
) -> str:
    migrated_mosquitto_conf: list[str] = []
    for line in mosquitto_conf.splitlines():
        if line.startswith("acl_file"):
            continue

        if line.startswith("password_file"):
            dynsec_plugin_configuration = [
                f"plugin {str(dynsec_lib_path)}",
                f"plugin_opt_config_file {str(dynsec_config_path)}",
            ]
            migrated_mosquitto_conf.extend(dynsec_plugin_configuration)
            continue

        migrated_mosquitto_conf.append(line)

    return "\n".join(migrated_mosquitto_conf)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--acl-file", required=True, type=str, help="Path to ACL file")
    parser.add_argument(
        "--pw-file", required=True, type=str, help="Path to password file"
    )
    parser.add_argument(
        "--conf", required=False, type=str, help="Path to mosquitto.conf file"
    )
    parser.add_argument(
        "--dynsec-lib",
        required=False,
        type=str,
        help="Path to mosquitto_dynamic_security.so/.dll",
    )

    args = parser.parse_args()
    acl_file_path = Path(args.acl_file)
    pw_file_path = Path(args.pw_file)

    dynsec_config_file_path = Path(__file__).parent.resolve() / "dynamic-security.json"

    if args.conf is not None:
        if args.dynsec_lib is None:
            print(
                "Error: Cannot migrate mosquitto.conf file. Reason: --dynsec-lib argument is missing"
            )
            return

        mosquitto_conf_path = Path(args.conf)
        mosquitto_conf = mosquitto_conf_path.read_text(encoding="utf-8")

        # Migrate mosquitto.conf
        migrated_mosquitto_conf = migrate_mosquitto_conf(
            mosquitto_conf,
            Path(args.dynsec_lib),
            dynsec_config_file_path,
        )

        # Backup old mosquitto.conf and afterwards write migrated mosquitto.conf file
        mosquitto_conf_path.with_suffix(".conf.old.dynsec").write_text(
            mosquitto_conf, encoding="utf-8"
        )
        mosquitto_conf_path.write_text(migrated_mosquitto_conf, encoding="utf-8")

    parsed_acl_file: AclFileConfig = AclFileConfig.parse_acl_file(acl_file_path)

    # Add global ACLs to users
    for _, user_acls in parsed_acl_file.user_acls.items():
        user_acls.extend(parsed_acl_file.global_acls)

    parsed_pw_file: PasswordFile = PasswordFile.parse_password_file(pw_file_path)

    # Migrate config and write to file
    dynsec_config = migrate_to_dynsec(parsed_acl_file, parsed_pw_file)
    dynsec_config_file_path.write_text(
        data=json.dumps(dynsec_config.asdict(), indent=4), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
