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

// components/webserver/web_stats.h
void web_stats_log_tag(
    uint32_t anchor_id,
    uint32_t tag_id,
    uint8_t  sync_seq,
    uint8_t  tag_seq,
    uint8_t  batt_pct,
    uint64_t uwb_ts);

void web_stats_log_hb(
    uint8_t  status,
    uint32_t uptime_ms,
    uint16_t sync_ms);

#ifdef __cplusplus
}
#endif
