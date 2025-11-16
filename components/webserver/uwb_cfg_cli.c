#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_err.h"
#include "cJSON.h"

#include "ble.h"
#include "uwb_cfg_cli.h"

static const char *TAG = "UWB_CFG_CLI";

/* Ugyanazok a TLV ID-k, mint a ble.c-ben */
#define T_NETWORK_ID      0x10
#define T_ZONE_ID         0x11
#define T_ANCHOR_ID       0x12
#define T_TX_ANT_DLY      0x13
#define T_RX_ANT_DLY      0x14
#define T_BIAS_TICKS      0x16
#define T_LOG_LEVEL       0x1F
#define T_HB_MS           0x20

#define T_SYN_PPM_MAX     0x30
#define T_SYN_JUMP_PPM    0x31
#define T_SYN_AB_GAP_MS   0x32
#define T_SYN_MS_EWMA_DEN 0x33
#define T_SYN_TK_EWMA_DEN 0x34
#define T_SYN_TK_MIN_MS   0x35
#define T_SYN_TK_MAX_MS   0x36
#define T_SYN_DTTX_MIN_MS 0x37
#define T_SYN_DTTX_MAX_MS 0x38
#define T_SYN_LOCK_NEED   0x39

#define T_PHY_CH        0x40
#define T_PHY_PLEN      0x41
#define T_PHY_PAC       0x42
#define T_PHY_TX_CODE   0x43
#define T_PHY_RX_CODE   0x44
#define T_PHY_SFD       0x45
#define T_PHY_BR        0x46
#define T_PHY_PHRMODE   0x47
#define T_PHY_PHRRATE   0x48
#define T_PHY_SFDTO     0x49
#define T_PHY_STS_MODE  0x4A
#define T_PHY_STS_LEN   0x4B
#define T_PHY_PDOA      0x4C

/* ===== Segéd: JSON érték -> int64 ===== */
static bool json_get_int64(cJSON *root, const char *key, int64_t *out)
{
    if (!root || !key || !out) return false;
    cJSON *it = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!it) return false;

    if (cJSON_IsNumber(it)) {
        *out = (int64_t)it->valuedouble;
        return true;
    }

    if (cJSON_IsString(it) && it->valuestring) {
        const char *s = it->valuestring;
        char *end = NULL;
        long long v = 0;

        /* hex támogatás: "0x..." vagy "0X..." */
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            v = strtoll(s + 2, &end, 16);
        } else {
            v = strtoll(s, &end, 10);
        }

        if (end == s) {
            ESP_LOGW(TAG, "key=%s: nem sikerült parse-olni: '%s'", key, s);
            return false;
        }
        *out = (int64_t)v;
        return true;
    }

    ESP_LOGW(TAG, "key=%s: nem szám típusú JSON", key);
    return false;
}

/* ===== Segéd: TLV írók (stacken max 256B) ===== */
static bool tlv_put_u8(uint8_t **w, uint8_t *end, uint8_t t, uint8_t v)
{
    if (*w + 2 + 1 > end) return false;
    *(*w)++ = t;
    *(*w)++ = 1;
    *(*w)++ = v;
    return true;
}

static bool tlv_put_u16(uint8_t **w, uint8_t *end, uint8_t t, uint16_t v)
{
    if (*w + 2 + 2 > end) return false;
    *(*w)++ = t;
    *(*w)++ = 2;
    *(*w)++ = (uint8_t)(v >> 8);
    *(*w)++ = (uint8_t)(v & 0xFF);
    return true;
}

static bool tlv_put_u32(uint8_t **w, uint8_t *end, uint8_t t, uint32_t v)
{
    if (*w + 2 + 4 > end) return false;
    *(*w)++ = t;
    *(*w)++ = 4;
    *(*w)++ = (uint8_t)(v >> 24);
    *(*w)++ = (uint8_t)(v >> 16);
    *(*w)++ = (uint8_t)(v >> 8);
    *(*w)++ = (uint8_t)(v & 0xFF);
    return true;
}

static bool tlv_put_i32(uint8_t **w, uint8_t *end, uint8_t t, int32_t v)
{
    return tlv_put_u32(w, end, t, (uint32_t)v);
}

/* ===== JSON -> TLV -> ble_send_set ===== */
esp_err_t uwb_cfg_cli_set_from_json(const cJSON *root, uint16_t req_id)
{
    if (!root) return ESP_ERR_INVALID_ARG;

    uint8_t  tlv[256];
    uint8_t *w   = tlv;
    uint8_t *end = tlv + sizeof(tlv);
    int64_t  tmp;
    bool     any = false;

    /* --- Base csoport --- */
    if (json_get_int64(root, "NETWORK_ID", &tmp)) {
        uint16_t v = (tmp < 0) ? 0 : (tmp > 0xFFFF ? 0xFFFF : (uint16_t)tmp);
        any |= tlv_put_u16(&w, end, T_NETWORK_ID, v);
    }
    if (json_get_int64(root, "ZONE_ID", &tmp)) {
        uint16_t v = (tmp < 0) ? 0 : (tmp > 0xFFFF ? 0xFFFF : (uint16_t)tmp);
        any |= tlv_put_u16(&w, end, T_ZONE_ID, v);
    }
    if (json_get_int64(root, "ANCHOR_ID", &tmp)) {
        uint32_t v = (tmp < 0) ? 0 : (uint32_t)tmp;
        any |= tlv_put_u32(&w, end, T_ANCHOR_ID, v);
    }
    if (json_get_int64(root, "HB_MS", &tmp)) {
        uint16_t v = (tmp < 0) ? 0 : (tmp > 0xFFFF ? 0xFFFF : (uint16_t)tmp);
        any |= tlv_put_u16(&w, end, T_HB_MS, v);
    }
    if (json_get_int64(root, "LOG_LEVEL", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_LOG_LEVEL, v);
    }
    if (json_get_int64(root, "TX_ANT_DLY", &tmp)) {
        int32_t v = (tmp < INT32_MIN) ? INT32_MIN : (tmp > INT32_MAX ? INT32_MAX : (int32_t)tmp);
        any |= tlv_put_i32(&w, end, T_TX_ANT_DLY, v);
    }
    if (json_get_int64(root, "RX_ANT_DLY", &tmp)) {
        int32_t v = (tmp < INT32_MIN) ? INT32_MIN : (tmp > INT32_MAX ? INT32_MAX : (int32_t)tmp);
        any |= tlv_put_i32(&w, end, T_RX_ANT_DLY, v);
    }
    if (json_get_int64(root, "BIAS_TICKS", &tmp)) {
        int32_t v = (tmp < INT32_MIN) ? INT32_MIN : (tmp > INT32_MAX ? INT32_MAX : (int32_t)tmp);
        any |= tlv_put_i32(&w, end, T_BIAS_TICKS, v);
    }

    /* --- Sync csoport --- */
    if (json_get_int64(root, "PPM_MAX", &tmp)) {
        uint16_t v = (tmp < 0) ? 0 : (tmp > 0xFFFF ? 0xFFFF : (uint16_t)tmp);
        any |= tlv_put_u16(&w, end, T_SYN_PPM_MAX, v);
    }
    if (json_get_int64(root, "JUMP_PPM", &tmp)) {
        uint16_t v = (tmp < 0) ? 0 : (tmp > 0xFFFF ? 0xFFFF : (uint16_t)tmp);
        any |= tlv_put_u16(&w, end, T_SYN_JUMP_PPM, v);
    }
    if (json_get_int64(root, "AB_GAP_MS", &tmp)) {
        uint16_t v = (tmp < 0) ? 0 : (tmp > 0xFFFF ? 0xFFFF : (uint16_t)tmp);
        any |= tlv_put_u16(&w, end, T_SYN_AB_GAP_MS, v);
    }
    if (json_get_int64(root, "MS_EWMA_DEN", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_SYN_MS_EWMA_DEN, v);
    }
    if (json_get_int64(root, "TK_EWMA_DEN", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_SYN_TK_EWMA_DEN, v);
    }
    if (json_get_int64(root, "TK_MIN_MS", &tmp)) {
        uint16_t v = (tmp < 0) ? 0 : (tmp > 0xFFFF ? 0xFFFF : (uint16_t)tmp);
        any |= tlv_put_u16(&w, end, T_SYN_TK_MIN_MS, v);
    }
    if (json_get_int64(root, "TK_MAX_MS", &tmp)) {
        uint16_t v = (tmp < 0) ? 0 : (tmp > 0xFFFF ? 0xFFFF : (uint16_t)tmp);
        any |= tlv_put_u16(&w, end, T_SYN_TK_MAX_MS, v);
    }
    if (json_get_int64(root, "DTTX_MIN_MS", &tmp)) {
        uint16_t v = (tmp < 0) ? 0 : (tmp > 0xFFFF ? 0xFFFF : (uint16_t)tmp);
        any |= tlv_put_u16(&w, end, T_SYN_DTTX_MIN_MS, v);
    }
    if (json_get_int64(root, "DTTX_MAX_MS", &tmp)) {
        uint16_t v = (tmp < 0) ? 0 : (tmp > 0xFFFF ? 0xFFFF : (uint16_t)tmp);
        any |= tlv_put_u16(&w, end, T_SYN_DTTX_MAX_MS, v);
    }
    if (json_get_int64(root, "LOCK_NEED", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_SYN_LOCK_NEED, v);
    }

    /* --- PHY csoport --- */
    if (json_get_int64(root, "PHY_CH", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_PHY_CH, v);
    }
    if (json_get_int64(root, "PHY_PLEN", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_PHY_PLEN, v);
    }
    if (json_get_int64(root, "PHY_PAC", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_PHY_PAC, v);
    }
    if (json_get_int64(root, "PHY_TX_CODE", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_PHY_TX_CODE, v);
    }
    if (json_get_int64(root, "PHY_RX_CODE", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_PHY_RX_CODE, v);
    }
    if (json_get_int64(root, "PHY_SFD", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_PHY_SFD, v);
    }
    if (json_get_int64(root, "PHY_BR", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_PHY_BR, v);
    }
    if (json_get_int64(root, "PHY_PHRMODE", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_PHY_PHRMODE, v);
    }
    if (json_get_int64(root, "PHY_PHRRATE", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_PHY_PHRRATE, v);
    }
    if (json_get_int64(root, "PHY_SFDTO", &tmp)) {
        uint16_t v = (tmp < 0) ? 0 : (tmp > 0xFFFF ? 0xFFFF : (uint16_t)tmp);
        any |= tlv_put_u16(&w, end, T_PHY_SFDTO, v);
    }
    if (json_get_int64(root, "PHY_STS_MODE", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_PHY_STS_MODE, v);
    }
    if (json_get_int64(root, "PHY_STS_LEN", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_PHY_STS_LEN, v);
    }
    if (json_get_int64(root, "PHY_PDOA", &tmp)) {
        uint8_t v = (tmp < 0) ? 0 : (tmp > 0xFF ? 0xFF : (uint8_t)tmp);
        any |= tlv_put_u8(&w, end, T_PHY_PDOA, v);
    }

    size_t len = (size_t)(w - tlv);

    if (!any || len == 0) {
        ESP_LOGW(TAG, "uwb_cfg_cli_set_from_json: nincs ismert kulcs a JSON-ben");
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "uwb_cfg_cli_set_from_json: req_id=%u, TLV len=%u", req_id, (unsigned)len);
    esp_err_t er = ble_send_set(req_id, tlv, (uint16_t)len);
    if (er != ESP_OK) {
        ESP_LOGE(TAG, "ble_send_set hiba: 0x%x", er);
    }
    return er;
}

/* A main.c ezt hívja */
esp_err_t uwb_cfg_cli_init(void)
{
    ESP_LOGI(TAG, "uwb_cfg_cli_init");
    return ESP_OK;
}

esp_err_t uwb_cfg_cli_get_all(uint16_t req_id)
{
    ESP_LOGI(TAG, "uwb_cfg_cli_get_all STUB, req_id=%u", req_id);
    /* ha később kell, hívhatod itt a ble_send_get-et is */
    return ESP_OK;
}

void uwb_cfg_cli_set_verbose(bool on)
{
    ESP_LOGI(TAG, "uwb_cfg_cli_set_verbose (jelenleg csak log), on=%d", (int)on);
}

void uwb_cfg_cli_set_log_progress(bool on)
{
    ESP_LOGI(TAG, "uwb_cfg_cli_set_log_progress (jelenleg csak log), on=%d", (int)on);
}
