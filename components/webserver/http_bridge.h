#pragma once
#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

void ble_http_bridge_init(void);
void http_register_routes(httpd_handle_t h);

#ifdef __cplusplus
}
#endif
