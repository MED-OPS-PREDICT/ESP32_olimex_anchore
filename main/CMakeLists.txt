idf_component_register(
    SRCS "main.c" "globals.c" "error_code_decoding.c"
    INCLUDE_DIRS "."
    REQUIRES webserver ble ethernet wifi_manager nvs_flash esp_netif esp_event
)
