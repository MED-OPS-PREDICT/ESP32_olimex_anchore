#pragma once

#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

void web_stats_init(void);
void web_stats_register_handlers(httpd_handle_t h);

#ifdef __cplusplus
}
#endif
