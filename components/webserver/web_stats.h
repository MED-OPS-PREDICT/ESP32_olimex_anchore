// web_stats.h
#pragma once

#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

// idle hook + egyéb init
void web_stats_init(void);

// HTTP route-ok regisztrálása (HTML + JSON)
void web_stats_register_handlers(httpd_handle_t server);

#ifdef __cplusplus
}
#endif
