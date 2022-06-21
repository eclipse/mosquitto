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
    auth_plugin_v5_handle_message
    plugin_control
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
    target_link_libraries(${BINARY} PRIVATE libmosquitto)
endforeach()
