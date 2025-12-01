idf_component_register(
    SRCS "ble.c" "pretty_print.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES nvs_flash bt log esp_netif esp_eth webserver
)
