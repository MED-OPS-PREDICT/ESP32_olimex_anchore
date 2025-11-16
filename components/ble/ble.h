#ifndef COMPONENTS_BLE_BLE_H
#define COMPONENTS_BLE_BLE_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/* notifier callback: (data, len, from_cfg) */
typedef void (*ble_notify_cb_t)(const uint8_t* data, uint16_t len, bool from_cfg);

// Nyers write a CFG karakterisztikára (OP_ACK, stb. küldéséhez)
esp_err_t ble_cfg_write_raw(const uint8_t *data, uint16_t len);

esp_err_t ble_start(const char* name_filter, ble_notify_cb_t cb);
esp_err_t ble_send_get(uint16_t req_id);
esp_err_t ble_send_set(uint16_t req_id, const uint8_t* tlv, uint16_t len);
void ble_register_notify_cb(ble_notify_cb_t cb);

/* --- közös protokoll opkódok (megosztva ble.c és http_server.c között) --- */
#define OP_GET    0x02
#define OP_START  0x82
#define OP_LINE   0x83
#define OP_ACK    0x84
#define OP_DONE   0x85
#define OP_ERR    0xE0

#endif /* COMPONENTS_BLE_BLE_H */
