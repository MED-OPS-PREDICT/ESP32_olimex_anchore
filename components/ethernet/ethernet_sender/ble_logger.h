#pragma once

#include <stdint.h>
#include <stdbool.h>

// UWBPacket – ugyanaz a layout, mint a DWM oldalon
#pragma pack(push,1)
typedef struct {
    uint8_t  prefix;
    uint8_t  version;
    uint8_t  sync_seq;     // ← ez jön előbb
    uint8_t  tag_seq;
    uint8_t  batt_pct;     // ← batt csak ezután
    uint32_t anchor_id;
    uint32_t tag_id;
    uint64_t timestamp;
} UWBPacket;
#pragma pack(pop)

// BLE notify callback szignatúra – ezt hívja a ble.c
void uwb_notify_cb(const uint8_t *data, uint16_t len, bool from_cfg);

// BLE/ETH KPI snapshot – ezt használja majd a web_stats.c
typedef struct {
    uint32_t rx_total;
    uint32_t tx_total;
    uint32_t err_total;
    double   rx_rate;   // pkt/s, az utolsó /api/stats óta eltelt időre
    double   tx_rate;   // jelenleg 0, de később bővíthető
    double   err_rate;  // hiba/s – most 0, ha nem számlálsz hibát
} ble_eth_kpi_t;

// KPI számlálók frissítése
void ble_logger_on_ble_packet(void);   // minden bejövő UWB BLE-n
void ble_logger_on_eth_packet(void);   // minden kimenő AES UDP csomag

// KPI snapshot olvasása és „since last” számlálók nullázása
void ble_logger_get_kpi(ble_eth_kpi_t *ble, ble_eth_kpi_t *eth);
