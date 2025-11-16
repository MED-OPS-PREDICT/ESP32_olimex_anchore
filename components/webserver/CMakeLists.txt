idf_component_register(
  SRCS
    "webserver.cpp"
    "http_server.c"
    "uwb_cfg_cli.c"
  INCLUDE_DIRS "."
  PRIV_REQUIRES main
  REQUIRES esp_http_server nvs_flash esp_netif spiffs mbedtls esp_timer json
)

spiffs_create_partition_image(spiffs spiffs FLASH_IN_PROJECT)
