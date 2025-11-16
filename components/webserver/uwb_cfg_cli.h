#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

// Inicializálás (jelenleg csak log és későbbi bővítéshez hely)
// Nem kezel BLE notify-okat: ez most a http_server.c-ben van megoldva.
esp_err_t uwb_cfg_cli_init(void);

// FIGYELEM:
// A teljes CFG GET-et jelenleg NEM ez a modul intézi, hanem a http_server.c
// (dwm_get_handler + ble_send_get + TLV stream feldolgozás).
// Ez a függvény csak helyfoglaló.
esp_err_t uwb_cfg_cli_get_all(uint16_t req_id);

// Verbose TLV logolás (opcionális)
void uwb_cfg_cli_set_verbose(bool on);

// Progress log (LINE x/y) kapcsolása
void uwb_cfg_cli_set_log_progress(bool on);

// JSON → TLV → ble_send_set()
// Ez a lényegi funkció: DWM konfiguráció beállítása.
esp_err_t uwb_cfg_cli_set_from_json(const cJSON *root, uint16_t req_id);

#ifdef __cplusplus
}
#endif
