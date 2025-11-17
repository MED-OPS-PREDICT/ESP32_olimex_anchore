idf_component_register(
    SRCS
        "ethernet.c"
        "ethernet_sender/ble_logger.c"
        "ethernet_sender/aes_sender.c"
    INCLUDE_DIRS
        .
        ethernet_sender
    REQUIRES esp_eth esp_netif nvs_flash driver esp_event log freertos
    PRIV_REQUIRES main
)
