To be fair this is simple plugin to provide extended password auth with gsasl.
To use this just load it in config and provide options with passwords like this.
Make sure you have libgsasl on your computer.

plugin ./mosquitto_gsasl_adapter.so
plugin_opt_loginpass publisher:publisher

this will allow you to use it with gsasl client adapter.