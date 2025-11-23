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
