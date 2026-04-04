#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t enabled;
    uint8_t dhcp;
    char ssid[33];
    char password[65];
    char ip[16];
    char mask[16];
    char gw[16];
    char dns1[16];
    char dns2[16];
} wifi_manager_config_t;

esp_err_t wifi_manager_init(void);

const wifi_manager_config_t* wifi_manager_get_config(void);
esp_err_t wifi_manager_set_config(const wifi_manager_config_t *cfg, bool keep_password_if_empty);

bool wifi_manager_is_enabled(void);
bool wifi_manager_should_run(void);

esp_err_t wifi_manager_start(void);
esp_err_t wifi_manager_stop(void);

bool wifi_manager_is_started(void);
bool wifi_manager_is_connected(void);
bool wifi_manager_has_ip(void);
const char* wifi_manager_get_ip_str(void);

#ifdef __cplusplus
}
#endif
