#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t udp_config_server_start(void);
void udp_config_on_ble_notify(const uint8_t *data, uint16_t len, bool from_cfg);

#ifdef __cplusplus
}
#endif
