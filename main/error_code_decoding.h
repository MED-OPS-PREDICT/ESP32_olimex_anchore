#pragma once
#include <stdint.h>
#include <stddef.h>

#define ST_BLE_LINK      0x01
#define ST_CFG_NOTIFY    0x02
#define ST_SYNC_PRELOCK  0x04
#define ST_SYNC_LOCK     0x08
#define ST_RX_WD_RESET   0x10
#define ST_RX_ERR_SEEN   0x20

const char *anchor_status_to_text(uint8_t st, char *buf, size_t buflen);
const char *anchor_status_short(uint8_t st);
