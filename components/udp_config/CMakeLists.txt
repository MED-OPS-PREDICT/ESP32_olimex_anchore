idf_component_register(
    SRCS "udp_config.c"
    INCLUDE_DIRS "."
    REQUIRES lwip json esp_netif esp_event
    PRIV_REQUIRES main webserver ble wifi_manager driver key_storage ethernet
)
