#pragma once

#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

void web_stats_init(void);
void web_stats_register_handlers(httpd_handle_t h);

void web_stats_ble_rx(bool ok);
void web_stats_ble_tx(bool ok);
void web_stats_eth_rx(bool ok);
void web_stats_eth_tx(bool ok);

#ifdef __cplusplus
}
#endif
