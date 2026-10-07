from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional


def format_config_value(v: Any):
    return str(v).lower() if isinstance(v, bool) else v


@dataclass
class ListenerConfig:
    port: int
    address: Optional[str] = ""
    cafile: Optional[Path] = None
    capath: Optional[Path] = None
    certfile: Optional[Path] = None
    crlfile: Optional[Path] = None
    dhparamfile: Optional[Path] = None
    disable_client_cert_date_checks: Optional[str] = None
    enable_proxy_protocol: Optional[str] = None
    http_dir: Optional[str] = None
    keyfile: Optional[Path] = None
    listener_allow_anonymous: Optional[bool] = None
    listener_auto_id_prefix: Optional[str] = None
    mount_point: Optional[str] = None
    protocol: Optional[str] = None
    proxy_protocol_v2_require_tls: Optional[bool] = None
    psk_hint: Optional[str] = None
    require_certificate: Optional[bool] = None
    use_identity_as_username: Optional[bool] = None
    websockets_origin: Optional[str] = None

    # Only for per_listener_settings=True
    allow_anonymous: Optional[bool] = None
    allow_zero_length_clientid: Optional[str] = None

    def __str__(self) -> str:
        result = f"listener {self.port} {self.address}\n"
        for k, v in self.__dict__.items():
            if k in ["port", "address"]:
                continue
            if v is not None:
                result += f"{k} {format_config_value(v)}\n"
        return result


@dataclass
class PluginConfig:
    path: Path
    options: dict = field(default_factory=dict)

    def __str__(self) -> str:
        result = f"plugin {self.path}\n"
        for k, v in self.options.items():
            if k.startswith("plugin_opt_"):
                result += f"{k} {v}\n"
            else:
                result += f"plugin_opt_{k} {v}\n"
        return result

@dataclass
class MQTTBridgeConfig:
    connection: str
    address: str
    topics: List[str]
    bridge_attempt_unsubscribe: bool = True
    bridge_cafile: Optional[str] = None
    bridge_identity: Optional[str] = None
    bridge_insecure: Optional[bool] = None
    bridge_max_topic_alias: Optional[int] = None
    bridge_outgoing_retain: Optional[bool] = None
    bridge_psk: Optional[str] = None
    bridge_protocol_version: Optional[str] = None
    cleansession: bool = False
    keepalive_interval: Optional[int] = None
    local_cleansession: bool = False
    notifications: bool = True
    remote_clientid: Optional[str] = None
    restart_timeout: Optional[int] = None
    try_private: Optional[bool] = None

    def __str__(self):
        result = ""
        for k, v in self.__dict__.items():
            if v is None:
                continue
            elif k == "topics":
                for item in v:
                    result += f"topic {item}\n"
            elif v is not None:
                result += f"{k} {format_config_value(v)}\n"
        return result

@dataclass
class BrokerConfig:
    listeners: List[ListenerConfig] = field(default_factory=list)
    plugins: List[PluginConfig] = field(default_factory=list)

    accept_protocol_versions: Optional[str] = None
    acl_file: Optional[str] = None
    allow_anonymous: Optional[bool] = None
    auto_id_prefix: Optional[str] = None
    autosave_interval: Optional[int] = None
    autosave_on_changes: Optional[bool] = None
    bridges: Optional[List[MQTTBridgeConfig]] = None
    enable_control_api: Optional[bool] = None
    global_max_clients: Optional[int] = None
    global_max_connections: Optional[int] = None
    global_plugin: Optional[PluginConfig] = None
    global_plugin_opts: Optional[dict] = None
    log_dest: Optional[str] = None
    log_type: Optional[str] = None
    max_connections: Optional[int] = None
    max_inflight_bytes: Optional[int] = None
    max_inflight_messages: Optional[int] = None
    max_keepalive: Optional[int] = None
    max_packet_size: Optional[int] = None
    max_queued_bytes: Optional[int] = None
    max_queued_messages: Optional[int] =None
    maximum_qos: Optional[int] = None
    message_size_limit: Optional[int] = None
    password_file: Optional[str] = None
    per_listener_settings: Optional[bool] = None
    persistence: Optional[str] = None
    persistence_file: Optional[str] = None
    persistence_location: Optional[str] = None
    psk_file: Optional[str] = None
    retain_available: Optional[bool] = None
    sys_interval: Optional[int] = None
    upgrade_outgoing_qos: Optional[bool] = None

    def __str__(self):
        result = ""
        if self.per_listener_settings is not None:
            result += f"per_listener_settings {format_config_value(self.per_listener_settings)}\n"
        for k, v in self.__dict__.items():
            if v is None:
                continue
            elif k in ["per_listener_settings"]:
                continue
            elif k == "global_plugin_opts" and self.global_plugin_opts is not None:
                for k, v in self.global_plugin_opts.items():
                    result += f"plugin_opt_{k} {v}\n"
            elif isinstance(v, list):
                for item in v:
                    result += f"{item}\n"
            elif v is not None:
                result += f"{k} {format_config_value(v)}\n"
        return result
