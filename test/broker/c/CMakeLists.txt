set(PLUGINS
    auth_plugin_acl
    auth_plugin_acl_change
    auth_plugin_acl_sub_denied
    auth_plugin_context_params
    auth_plugin_delayed
    auth_plugin_extended_multiple
    auth_plugin_extended_reauth
    auth_plugin_extended_single
    auth_plugin_extended_single2
    auth_plugin_id_change
    auth_plugin_msg_params
    auth_plugin_publish
    auth_plugin_pwd
    auth_plugin_v2
    auth_plugin_v3
    auth_plugin_v4
    auth_plugin_v5
    auth_plugin_v5_control
    bad_v1
    bad_v2_1
    bad_v2_2
    bad_v2_3
    bad_v2_4
    bad_v2_5
    bad_v2_6
    bad_v2_7
    bad_v3_1
    bad_v3_2
    bad_v3_3
    bad_v3_4
    bad_v3_5
    bad_v3_6
    bad_v3_7
    bad_v4_1
    bad_v4_2
    bad_v4_3
    bad_v4_4
    bad_v5_1
    bad_v6
    bad_vnone_1
    plugin_control
    plugin_evt_client_offline
    plugin_evt_message_in
    plugin_evt_message_out
    plugin_evt_persist_client_update
    plugin_evt_psk_key
    plugin_evt_subscribe
    plugin_evt_tick
    plugin_evt_unsubscribe
)

foreach(PLUGIN ${PLUGINS})
    add_library(${PLUGIN} MODULE
        ${PLUGIN}.c
    )
    set_property(TARGET ${PLUGIN}
        PROPERTY PREFIX ""
    )
    target_link_libraries(${PLUGIN} PRIVATE mosquitto)
endforeach()

set(BINARIES
    08-tls-psk-pub
    08-tls-psk-bridge
)

foreach(BINARY ${BINARIES})
    add_executable(${BINARY}
        ${BINARY}.c
    )
    set_property(TARGET ${BINARY}
        PROPERTY SUFFIX .test
    )
    target_link_libraries(${BINARY} PRIVATE common-options libmosquitto)
endforeach()
