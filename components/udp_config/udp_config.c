#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"

#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "cJSON.h"

#include "globals.h"
#include "webserver.hpp"
#include "wifi_manager.h"
#include "ble.h"
#include "uwb_cfg_cli.h"
#include "ethernet.h"
#include "aes_sender.h"
#include "key_storage.h"
#include "udp_config.h"

static const char *TAG = "udp_cfg";
static const uint16_t UDP_CONFIG_DEFAULT_PORT = 12345;
static const char *NVS_NS = "cfg";
static const char *NVS_KEY = "esp_cfg";
static const char *NVS_KEY_BLE = "ble_cfg";
static const char *NVS_SECURE_NS = "secure";
static const char *NVS_KEY_MGMT_TOKEN = "mgmt_token";

/* --- kompatibilis másolat a webserver.cpp EspCfg struktúrájáról --- */
typedef struct {
    uint16_t NETWORK_ID;
    uint16_t ZONE_ID;
    uint32_t ANCHOR_ID;
    uint16_t HB_MS;
    uint8_t  LOG_LEVEL;
    int32_t  TX_ANT_DLY;
    int32_t  RX_ANT_DLY;
    int32_t  BIAS_TICKS;
    uint8_t  PHY_CH;
    uint16_t PHY_SFDTO;

    uint32_t GW_ID;

    char ZONE_CTRL_IP[16];
    uint16_t ZONE_CTRL_PORT;
    uint8_t  ZONE_CTRL_EN;

    char MAIN_IP[16];
    uint16_t MAIN_PORT;
    uint8_t  MAIN_EN;

    char SERVICE_IP[16];
    uint16_t SERVICE_PORT;
    uint8_t  SERVICE_EN;

    char aes_key_hex[65];

    uint8_t ETH_MODE;
    char    ETH_IP[16];
    char    ETH_MASK[16];
    char    ETH_GW[16];

    char ZONE_NAME[32];
    char DEVICE_NAME[32];
    char DEVICE_DESC[64];
} persisted_cfg_t;

/* --- DWM/TLV feldolgozás az UDP GET-hez --- */
typedef struct {
    uint16_t len;
    bool from_cfg;
    uint8_t data[];
} frame_t;

enum {
    H_NETWORK_ID = 0, H_ZONE_ID, H_ANCHOR_ID, H_HB_MS, H_LOG_LEVEL,
    H_TX_ANT_DLY, H_RX_ANT_DLY, H_BIAS_TICKS,
    H_PHY_CH, H_PHY_SFDTO,
    H_SYN_PPM_MAX, H_SYN_JUMP_PPM, H_SYN_AB_GAP_MS, H_SYN_MS_EWMA_DEN,
    H_SYN_TK_EWMA_DEN, H_SYN_TK_MIN_MS, H_SYN_TK_MAX_MS,
    H_SYN_DTTX_MIN_MS, H_SYN_DTTX_MAX_MS, H_SYN_LOCK_NEED,
    H_PHY_PLEN, H_PHY_PAC, H_PHY_TX_CODE, H_PHY_RX_CODE,
    H_PHY_SFD, H_PHY_BR, H_PHY_PHRMODE, H_PHY_PHRRATE,
    H_PHY_STS_MODE, H_PHY_STS_LEN, H_PHY_PDOA,
    H_STATUS, H_UPTIME_MS, H_SYNC_MS,
    H__COUNT
};

static struct {
    uint16_t network_id, zone_id, hb_ms, phy_sfdto;
    uint32_t anchor_id;
    int32_t  tx_ant_dly, rx_ant_dly, bias_ticks;
    uint8_t  log_level, phy_ch;

    uint16_t syn_ppm_max, syn_jump_ppm, syn_ab_gap_ms,
             syn_tk_min_ms, syn_tk_max_ms,
             syn_dttx_min_ms, syn_dttx_max_ms;
    uint8_t  syn_ms_ewma_den, syn_tk_ewma_den, syn_lock_need;

    uint8_t  phy_plen, phy_pac, phy_tx_code, phy_rx_code, phy_sfd, phy_br,
             phy_phrmode, phy_phrrate, phy_sts_mode, phy_sts_len, phy_pdoa;

    uint8_t  status;
    uint32_t uptime_ms, sync_ms;
    bool     have[H__COUNT];
} s_dwm_cfg;

static QueueHandle_t s_dwm_q = NULL;
static TaskHandle_t s_dwm_worker = NULL;
static TaskHandle_t s_dwm_refresh_task_handle = NULL;
static TaskHandle_t s_hb_task_handle = NULL;
static SemaphoreHandle_t s_dwm_sem = NULL;
static SemaphoreHandle_t s_dwm_lock = NULL;
static SemaphoreHandle_t s_dwm_refresh_sem = NULL;
static volatile bool s_dwm_cfg_done = false;
static volatile bool s_dwm_refresh_in_progress = false;
static volatile bool s_dwm_first_line_seen = false;
static volatile TickType_t s_dwm_last_line_tick = 0;
static TickType_t s_dwm_last_refresh_tick = 0;
static bool s_dwm_have_snapshot = false;
static uint16_t s_dwm_req_id = 0;
static uint16_t s_dwm_active_req_id = 0;
static uint8_t s_tlv_section = 1;
static bool s_udp_task_started = false;

static inline uint16_t rd16be(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static inline uint32_t rd32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void safe_copy(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0) return;
    if (!src) src = "";
    strncpy(dst, src, dst_sz - 1);
    dst[dst_sz - 1] = 0;
}

static void ip4_to_cstr(const ip4_addr_t *ip, char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return;
    snprintf(out, out_sz, IPSTR, IP2STR(ip));
}

static void apply_ip4_from_str(const char *src, ip4_addr_t *dst)
{
    if (!src || !dst) return;
    ip4addr_aton(src, dst);
}

static const cJSON *obj_get(const cJSON *obj, const char *key);

static bool const_time_str_equal(const char *a, const char *b)
{
    size_t la = a ? strlen(a) : 0;
    size_t lb = b ? strlen(b) : 0;
    size_t n = (la > lb) ? la : lb;
    unsigned char diff = (unsigned char)(la ^ lb);

    for (size_t i = 0; i < n; ++i) {
        unsigned char ca = (a && i < la) ? (unsigned char)a[i] : 0U;
        unsigned char cb = (b && i < lb) ? (unsigned char)b[i] : 0U;
        diff |= (unsigned char)(ca ^ cb);
    }

    return diff == 0;
}

static esp_err_t load_udp_auth_secret(char *out, size_t out_sz)
{
    if (!out || out_sz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    out[0] = 0;

    nvs_handle_t h;
    if (nvs_open(NVS_SECURE_NS, NVS_READONLY, &h) == ESP_OK) {
        size_t len = out_sz;
        esp_err_t err = nvs_get_str(h, NVS_KEY_MGMT_TOKEN, out, &len);
        nvs_close(h);
        if (err == ESP_OK && out[0] != 0) {
            return ESP_OK;
        }
    }

    if (key_storage_load(out) && out[0] != 0) {
        return ESP_OK;
    }

    out[0] = 0;
    return ESP_ERR_NOT_FOUND;
}

static esp_err_t validate_udp_auth(const cJSON *root)
{
    const cJSON *auth_item = obj_get(root, "auth");
    char expected[128] = {0};

    if (!cJSON_IsString(auth_item) || !auth_item->valuestring || auth_item->valuestring[0] == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = load_udp_auth_secret(expected, sizeof(expected));
    if (err != ESP_OK) {
        return err;
    }

    return const_time_str_equal(auth_item->valuestring, expected) ? ESP_OK : ESP_ERR_INVALID_CRC;
}


static void reset_dwm_cfg(void)
{
    memset(&s_dwm_cfg, 0, sizeof(s_dwm_cfg));
    s_tlv_section = 1;
}


static bool dwm_has_any_data(void)
{
    for (size_t i = 0; i < H__COUNT; ++i) {
        if (s_dwm_cfg.have[i]) {
            return true;
        }
    }
    return false;
}

static void dwm_request_refresh(bool force)
{
    if (!s_dwm_refresh_sem) return;
    if (force || !s_dwm_refresh_in_progress) {
        (void)xSemaphoreGive(s_dwm_refresh_sem);
    }
}

static void drain_dwm_queue(void)
{
    frame_t *f = NULL;
    while (s_dwm_q && xQueueReceive(s_dwm_q, &f, 0) == pdTRUE) {
        if (f) {
            free(f);
        }
    }
}

static bool load_cfg_from_nvs(persisted_cfg_t *cfg)
{
    if (!cfg) return false;

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return false;
    }

    size_t sz = sizeof(*cfg);
    err = nvs_get_blob(h, NVS_KEY, cfg, &sz);
    nvs_close(h);

    return (err == ESP_OK && sz <= sizeof(*cfg));
}

static esp_err_t save_cfg_to_nvs(const persisted_cfg_t *cfg)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_blob(h, NVS_KEY, cfg, sizeof(*cfg));
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

static bool load_ble_cfg_from_nvs(web_ble_cfg_t *cfg)
{
    if (!cfg) return false;

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return false;
    }

    size_t sz = sizeof(*cfg);
    err = nvs_get_blob(h, NVS_KEY_BLE, cfg, &sz);
    nvs_close(h);
    return (err == ESP_OK && sz <= sizeof(*cfg));
}

static esp_err_t save_ble_cfg_to_nvs(const web_ble_cfg_t *cfg)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_blob(h, NVS_KEY_BLE, cfg, sizeof(*cfg));
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

static void sync_cfg_from_runtime(persisted_cfg_t *cfg)
{
    if (!cfg) return;

    cfg->GW_ID = IPS.gw_id;
    if (IPS.hb_ms > 0) {
        cfg->HB_MS = (uint16_t)IPS.hb_ms;
    }

    ip4_to_cstr(&NET.ip, cfg->ETH_IP, sizeof(cfg->ETH_IP));
    ip4_to_cstr(&NET.mask, cfg->ETH_MASK, sizeof(cfg->ETH_MASK));
    ip4_to_cstr(&NET.gw, cfg->ETH_GW, sizeof(cfg->ETH_GW));
    cfg->ETH_MODE = NET.use_dhcp ? 0 : 1;

    ip4_to_cstr(&IPS.dest[0].dest_ip, cfg->ZONE_CTRL_IP, sizeof(cfg->ZONE_CTRL_IP));
    cfg->ZONE_CTRL_PORT = IPS.dest[0].dest_port;
    cfg->ZONE_CTRL_EN   = IPS.dest[0].enabled;

    ip4_to_cstr(&IPS.dest[1].dest_ip, cfg->MAIN_IP, sizeof(cfg->MAIN_IP));
    cfg->MAIN_PORT = IPS.dest[1].dest_port;
    cfg->MAIN_EN   = IPS.dest[1].enabled;

    ip4_to_cstr(&IPS.dest[2].dest_ip, cfg->SERVICE_IP, sizeof(cfg->SERVICE_IP));
    cfg->SERVICE_PORT = IPS.dest[2].dest_port;
    cfg->SERVICE_EN   = IPS.dest[2].enabled;

    if (cfg->aes_key_hex[0] == 0) {
        char key_buf[65] = {0};
        if (key_storage_load(key_buf)) {
            safe_copy(cfg->aes_key_hex, sizeof(cfg->aes_key_hex), key_buf);
        }
    }
}

static void apply_runtime_from_cfg(const persisted_cfg_t *cfg)
{
    if (!cfg) return;

    NET.use_dhcp = (cfg->ETH_MODE == 0);
    apply_ip4_from_str(cfg->ETH_IP, &NET.ip);
    apply_ip4_from_str(cfg->ETH_MASK, &NET.mask);
    apply_ip4_from_str(cfg->ETH_GW, &NET.gw);

    IPS.gw_id = cfg->GW_ID;
    if (cfg->HB_MS > 0) {
        IPS.hb_ms = cfg->HB_MS;
    }

    apply_ip4_from_str(cfg->ZONE_CTRL_IP, &IPS.dest[0].dest_ip);
    IPS.dest[0].dest_port = cfg->ZONE_CTRL_PORT;
    IPS.dest[0].enabled   = cfg->ZONE_CTRL_EN;

    apply_ip4_from_str(cfg->MAIN_IP, &IPS.dest[1].dest_ip);
    IPS.dest[1].dest_port = cfg->MAIN_PORT;
    IPS.dest[1].enabled   = cfg->MAIN_EN;

    apply_ip4_from_str(cfg->SERVICE_IP, &IPS.dest[2].dest_ip);
    IPS.dest[2].dest_port = cfg->SERVICE_PORT;
    IPS.dest[2].enabled   = cfg->SERVICE_EN;

    if (cfg->aes_key_hex[0] != 0) {
        aes_sender_set_key_hex(cfg->aes_key_hex);
        (void)key_storage_save(cfg->aes_key_hex);
    }

    ethernet_reapply_ip_from_net();
}

static bool any_telemetry_dest_enabled(void)
{
    for (int i = 0; i < 3; ++i) {
        if (IPS.dest[i].enabled && IPS.dest[i].dest_port != 0 && IPS.dest[i].dest_ip.addr != 0) {
            return true;
        }
    }
    return false;
}

static void build_periodic_hb_line(char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return;

    uint16_t zone_id = esp_cfg_get_zone_id();
    snprintf(out, out_sz,
             "HB: HB status=%" PRIu8 " uptime=%" PRIu32 " ms sync_ms=%" PRIu32 " zone_id=0x%04X",
             (uint8_t)g_hb_status,
             (uint32_t)g_hb_uptime,
             (uint32_t)g_hb_sync_ms,
             (unsigned)zone_id);
}

static void restore_telemetry_runtime(void)
{
    aes_sender_init();

    persisted_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (load_cfg_from_nvs(&cfg)) {
        apply_runtime_from_cfg(&cfg);
        ESP_LOGI(TAG, "telemetry runtime restored from persisted config");
        return;
    }

    char key_buf[65] = {0};
    if (key_storage_load(key_buf) && key_buf[0] != 0) {
        aes_sender_set_key_hex(key_buf);
        ESP_LOGI(TAG, "telemetry AES key restored from key storage");
    }
}

static void telemetry_hb_task(void *arg)
{
    (void)arg;

    TickType_t last_wake = xTaskGetTickCount();
    for (;;) {
        uint32_t hb_ms = IPS.hb_ms;
        if (hb_ms == 0) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            last_wake = xTaskGetTickCount();
            continue;
        }

        vTaskDelayUntil(&last_wake, pdMS_TO_TICKS(hb_ms));

        if (!any_telemetry_dest_enabled()) {
            continue;
        }

        char line[160];
        build_periodic_hb_line(line, sizeof(line));
        aes_sender_send_line(line);
    }
}

static const cJSON *obj_get(const cJSON *obj, const char *key)
{
    return cJSON_GetObjectItemCaseSensitive((cJSON *)obj, key);
}

static bool json_copy_string_item(const cJSON *obj, const char *key, char *out, size_t out_sz)
{
    const cJSON *item = obj_get(obj, key);
    if (!cJSON_IsString(item) || !item->valuestring) return false;
    safe_copy(out, out_sz, item->valuestring);
    return true;
}

static bool json_copy_u8_item(const cJSON *obj, const char *key, uint8_t *out)
{
    const cJSON *item = obj_get(obj, key);
    if (!item) return false;
    if (cJSON_IsBool(item)) {
        *out = cJSON_IsTrue(item) ? 1 : 0;
        return true;
    }
    if (cJSON_IsNumber(item)) {
        *out = (uint8_t)item->valueint;
        return true;
    }
    return false;
}

static bool json_copy_u16_item(const cJSON *obj, const char *key, uint16_t *out)
{
    const cJSON *item = obj_get(obj, key);
    if (cJSON_IsNumber(item)) {
        *out = (uint16_t)item->valueint;
        return true;
    }
    if (cJSON_IsString(item) && item->valuestring) {
        *out = (uint16_t)strtoul(item->valuestring, NULL, 0);
        return true;
    }
    return false;
}

static bool json_copy_u32_item(const cJSON *obj, const char *key, uint32_t *out)
{
    const cJSON *item = obj_get(obj, key);
    if (cJSON_IsNumber(item)) {
        *out = (uint32_t)item->valuedouble;
        return true;
    }
    if (cJSON_IsString(item) && item->valuestring) {
        *out = (uint32_t)strtoul(item->valuestring, NULL, 0);
        return true;
    }
    return false;
}

static bool json_copy_i32_item(const cJSON *obj, const char *key, int32_t *out)
{
    const cJSON *item = obj_get(obj, key);
    if (cJSON_IsNumber(item)) {
        *out = (int32_t)item->valuedouble;
        return true;
    }
    if (cJSON_IsString(item) && item->valuestring) {
        *out = (int32_t)strtol(item->valuestring, NULL, 0);
        return true;
    }
    return false;
}

static void add_string_or_empty(cJSON *obj, const char *key, const char *value)
{
    cJSON_AddStringToObject(obj, key, value ? value : "");
}

static cJSON *build_system_json_obj(void)
{
    persisted_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)load_cfg_from_nvs(&cfg);
    sync_cfg_from_runtime(&cfg);

    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;

    cJSON_AddNumberToObject(obj, "GW_ID", (double)cfg.GW_ID);
    cJSON_AddNumberToObject(obj, "HB_MS", (double)cfg.HB_MS);
    cJSON_AddNumberToObject(obj, "ETH_MODE", cfg.ETH_MODE);
    add_string_or_empty(obj, "ETH_IP", cfg.ETH_IP);
    add_string_or_empty(obj, "ETH_MASK", cfg.ETH_MASK);
    add_string_or_empty(obj, "ETH_GW", cfg.ETH_GW);

    add_string_or_empty(obj, "ZONE_CTRL_IP", cfg.ZONE_CTRL_IP);
    cJSON_AddNumberToObject(obj, "ZONE_CTRL_PORT", cfg.ZONE_CTRL_PORT);
    cJSON_AddNumberToObject(obj, "ZONE_CTRL_EN", cfg.ZONE_CTRL_EN);

    add_string_or_empty(obj, "MAIN_IP", cfg.MAIN_IP);
    cJSON_AddNumberToObject(obj, "MAIN_PORT", cfg.MAIN_PORT);
    cJSON_AddNumberToObject(obj, "MAIN_EN", cfg.MAIN_EN);

    add_string_or_empty(obj, "SERVICE_IP", cfg.SERVICE_IP);
    cJSON_AddNumberToObject(obj, "SERVICE_PORT", cfg.SERVICE_PORT);
    cJSON_AddNumberToObject(obj, "SERVICE_EN", cfg.SERVICE_EN);

    cJSON_AddBoolToObject(obj, "AES_KEY_SET", cfg.aes_key_hex[0] != 0);
    add_string_or_empty(obj, "ZONE_NAME", cfg.ZONE_NAME);
    add_string_or_empty(obj, "DEVICE_NAME", cfg.DEVICE_NAME);
    add_string_or_empty(obj, "DEVICE_DESC", cfg.DEVICE_DESC);

    return obj;
}

static cJSON *build_ble_json_obj(void)
{
    web_ble_cfg_t cfg = {0};
    const web_ble_cfg_t *live = web_ble_cfg_get();
    if (live) {
        cfg = *live;
    } else {
        (void)load_ble_cfg_from_nvs(&cfg);
    }

    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;

    add_string_or_empty(obj, "BLE_NAME", cfg.name);
    add_string_or_empty(obj, "BLE_SVC_UUID", cfg.svc_uuid);
    add_string_or_empty(obj, "BLE_DATA_UUID", cfg.data_uuid);
    add_string_or_empty(obj, "BLE_CFG_UUID", cfg.cfg_uuid);
    cJSON_AddNumberToObject(obj, "BLE_REQ_ID", cfg.req_id);
    return obj;
}

static cJSON *build_wifi_json_obj(void)
{
    const wifi_manager_config_t *cfg = wifi_manager_get_config();
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;

    if (!cfg) {
        return obj;
    }

    cJSON_AddBoolToObject(obj, "enabled", cfg->enabled != 0);
    cJSON_AddBoolToObject(obj, "dhcp", cfg->dhcp != 0);
    add_string_or_empty(obj, "ssid", cfg->ssid);
    cJSON_AddBoolToObject(obj, "password_set", cfg->password[0] != 0);
    add_string_or_empty(obj, "ip", cfg->ip);
    add_string_or_empty(obj, "mask", cfg->mask);
    add_string_or_empty(obj, "gw", cfg->gw);
    add_string_or_empty(obj, "dns1", cfg->dns1);
    add_string_or_empty(obj, "dns2", cfg->dns2);
    return obj;
}

static esp_err_t system_apply_from_json(const cJSON *system_obj)
{
    if (!cJSON_IsObject(system_obj)) return ESP_ERR_INVALID_ARG;

    persisted_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)load_cfg_from_nvs(&cfg);
    sync_cfg_from_runtime(&cfg);

    (void)json_copy_u32_item(system_obj, "GW_ID", &cfg.GW_ID);
    (void)json_copy_u16_item(system_obj, "HB_MS", &cfg.HB_MS);
    (void)json_copy_u8_item(system_obj, "ETH_MODE", &cfg.ETH_MODE);
    (void)json_copy_string_item(system_obj, "ETH_IP", cfg.ETH_IP, sizeof(cfg.ETH_IP));
    (void)json_copy_string_item(system_obj, "ETH_MASK", cfg.ETH_MASK, sizeof(cfg.ETH_MASK));
    (void)json_copy_string_item(system_obj, "ETH_GW", cfg.ETH_GW, sizeof(cfg.ETH_GW));

    (void)json_copy_string_item(system_obj, "ZONE_CTRL_IP", cfg.ZONE_CTRL_IP, sizeof(cfg.ZONE_CTRL_IP));
    (void)json_copy_u16_item(system_obj, "ZONE_CTRL_PORT", &cfg.ZONE_CTRL_PORT);
    (void)json_copy_u8_item(system_obj, "ZONE_CTRL_EN", &cfg.ZONE_CTRL_EN);

    (void)json_copy_string_item(system_obj, "MAIN_IP", cfg.MAIN_IP, sizeof(cfg.MAIN_IP));
    (void)json_copy_u16_item(system_obj, "MAIN_PORT", &cfg.MAIN_PORT);
    (void)json_copy_u8_item(system_obj, "MAIN_EN", &cfg.MAIN_EN);

    (void)json_copy_string_item(system_obj, "SERVICE_IP", cfg.SERVICE_IP, sizeof(cfg.SERVICE_IP));
    (void)json_copy_u16_item(system_obj, "SERVICE_PORT", &cfg.SERVICE_PORT);
    (void)json_copy_u8_item(system_obj, "SERVICE_EN", &cfg.SERVICE_EN);

    (void)json_copy_string_item(system_obj, "AES_KEY", cfg.aes_key_hex, sizeof(cfg.aes_key_hex));
    (void)json_copy_string_item(system_obj, "ZONE_NAME", cfg.ZONE_NAME, sizeof(cfg.ZONE_NAME));
    (void)json_copy_string_item(system_obj, "DEVICE_NAME", cfg.DEVICE_NAME, sizeof(cfg.DEVICE_NAME));
    (void)json_copy_string_item(system_obj, "DEVICE_DESC", cfg.DEVICE_DESC, sizeof(cfg.DEVICE_DESC));

    apply_runtime_from_cfg(&cfg);
    return save_cfg_to_nvs(&cfg);
}

static esp_err_t ble_apply_from_json(const cJSON *ble_obj)
{
    if (!cJSON_IsObject(ble_obj)) return ESP_ERR_INVALID_ARG;

    web_ble_cfg_t cfg = {0};
    const web_ble_cfg_t *live = web_ble_cfg_get();
    if (live) {
        cfg = *live;
    } else {
        (void)load_ble_cfg_from_nvs(&cfg);
    }

    (void)json_copy_string_item(ble_obj, "BLE_NAME", cfg.name, sizeof(cfg.name));
    (void)json_copy_string_item(ble_obj, "BLE_SVC_UUID", cfg.svc_uuid, sizeof(cfg.svc_uuid));
    (void)json_copy_string_item(ble_obj, "BLE_DATA_UUID", cfg.data_uuid, sizeof(cfg.data_uuid));
    (void)json_copy_string_item(ble_obj, "BLE_CFG_UUID", cfg.cfg_uuid, sizeof(cfg.cfg_uuid));
    (void)json_copy_u16_item(ble_obj, "BLE_REQ_ID", &cfg.req_id);

    esp_err_t err = save_ble_cfg_to_nvs(&cfg);
    if (err != ESP_OK) {
        return err;
    }

    web_ble_cfg_t *live_mut = (web_ble_cfg_t *)web_ble_cfg_get();
    if (live_mut) {
        *live_mut = cfg;
    }

    if (cfg.svc_uuid[0] && cfg.data_uuid[0] && cfg.cfg_uuid[0]) {
        (void)ble_set_uuids_from_strings(cfg.svc_uuid, cfg.data_uuid, cfg.cfg_uuid);
    }
    return ble_restart_with_filter(cfg.name[0] ? cfg.name : "");
}

static esp_err_t wifi_apply_from_json(const cJSON *wifi_obj)
{
    if (!cJSON_IsObject(wifi_obj)) return ESP_ERR_INVALID_ARG;

    wifi_manager_config_t next = {0};
    const wifi_manager_config_t *cur = wifi_manager_get_config();
    if (cur) {
        next = *cur;
    }

    (void)json_copy_u8_item(wifi_obj, "enabled", &next.enabled);
    (void)json_copy_u8_item(wifi_obj, "dhcp", &next.dhcp);
    (void)json_copy_string_item(wifi_obj, "ssid", next.ssid, sizeof(next.ssid));
    (void)json_copy_string_item(wifi_obj, "password", next.password, sizeof(next.password));
    (void)json_copy_string_item(wifi_obj, "ip", next.ip, sizeof(next.ip));
    (void)json_copy_string_item(wifi_obj, "mask", next.mask, sizeof(next.mask));
    (void)json_copy_string_item(wifi_obj, "gw", next.gw, sizeof(next.gw));
    (void)json_copy_string_item(wifi_obj, "dns1", next.dns1, sizeof(next.dns1));
    (void)json_copy_string_item(wifi_obj, "dns2", next.dns2, sizeof(next.dns2));

    esp_err_t err = wifi_manager_set_config(&next, true);
    if (err != ESP_OK) {
        return err;
    }

    if (!next.enabled || next.ssid[0] == 0) {
        return wifi_manager_stop();
    }

    return wifi_manager_start();
}

static void build_dwm_json(cJSON *j)
{
    if (s_dwm_cfg.have[H_STATUS]) cJSON_AddNumberToObject(j, "STATUS", s_dwm_cfg.status);
    if (s_dwm_cfg.have[H_UPTIME_MS]) cJSON_AddNumberToObject(j, "UPTIME_MS", s_dwm_cfg.uptime_ms);
    if (s_dwm_cfg.have[H_SYNC_MS]) cJSON_AddNumberToObject(j, "SYNC_MS", s_dwm_cfg.sync_ms);
    if (s_dwm_cfg.have[H_NETWORK_ID]) cJSON_AddNumberToObject(j, "NETWORK_ID", s_dwm_cfg.network_id);
    if (s_dwm_cfg.have[H_ZONE_ID]) {
        char hex[8];
        cJSON_AddNumberToObject(j, "ZONE_ID", s_dwm_cfg.zone_id);
        snprintf(hex, sizeof(hex), "0x%04X", s_dwm_cfg.zone_id);
        cJSON_AddStringToObject(j, "ZONE_ID_HEX", hex);
    }
    if (s_dwm_cfg.have[H_ANCHOR_ID]) {
        char hex[11];
        snprintf(hex, sizeof(hex), "0x%08" PRIX32, (uint32_t)s_dwm_cfg.anchor_id);
        cJSON_AddStringToObject(j, "ANCHOR_ID", hex);
    }
    if (s_dwm_cfg.have[H_HB_MS]) cJSON_AddNumberToObject(j, "HB_MS", s_dwm_cfg.hb_ms);
    if (s_dwm_cfg.have[H_LOG_LEVEL]) cJSON_AddNumberToObject(j, "LOG_LEVEL", s_dwm_cfg.log_level);
    if (s_dwm_cfg.have[H_TX_ANT_DLY]) cJSON_AddNumberToObject(j, "TX_ANT_DLY", s_dwm_cfg.tx_ant_dly);
    if (s_dwm_cfg.have[H_RX_ANT_DLY]) cJSON_AddNumberToObject(j, "RX_ANT_DLY", s_dwm_cfg.rx_ant_dly);
    if (s_dwm_cfg.have[H_BIAS_TICKS]) cJSON_AddNumberToObject(j, "BIAS_TICKS", s_dwm_cfg.bias_ticks);
    if (s_dwm_cfg.have[H_PHY_CH]) cJSON_AddNumberToObject(j, "PHY_CH", s_dwm_cfg.phy_ch);
    if (s_dwm_cfg.have[H_PHY_SFDTO]) cJSON_AddNumberToObject(j, "PHY_SFDTO", s_dwm_cfg.phy_sfdto);
    if (s_dwm_cfg.have[H_SYN_PPM_MAX]) cJSON_AddNumberToObject(j, "PPM_MAX", s_dwm_cfg.syn_ppm_max);
    if (s_dwm_cfg.have[H_SYN_JUMP_PPM]) cJSON_AddNumberToObject(j, "JUMP_PPM", s_dwm_cfg.syn_jump_ppm);
    if (s_dwm_cfg.have[H_SYN_AB_GAP_MS]) cJSON_AddNumberToObject(j, "AB_GAP_MS", s_dwm_cfg.syn_ab_gap_ms);
    if (s_dwm_cfg.have[H_SYN_MS_EWMA_DEN]) cJSON_AddNumberToObject(j, "MS_EWMA_DEN", s_dwm_cfg.syn_ms_ewma_den);
    if (s_dwm_cfg.have[H_SYN_TK_EWMA_DEN]) cJSON_AddNumberToObject(j, "TK_EWMA_DEN", s_dwm_cfg.syn_tk_ewma_den);
    if (s_dwm_cfg.have[H_SYN_TK_MIN_MS]) cJSON_AddNumberToObject(j, "TK_MIN_MS", s_dwm_cfg.syn_tk_min_ms);
    if (s_dwm_cfg.have[H_SYN_TK_MAX_MS]) cJSON_AddNumberToObject(j, "TK_MAX_MS", s_dwm_cfg.syn_tk_max_ms);
    if (s_dwm_cfg.have[H_SYN_DTTX_MIN_MS]) cJSON_AddNumberToObject(j, "DTTX_MIN_MS", s_dwm_cfg.syn_dttx_min_ms);
    if (s_dwm_cfg.have[H_SYN_DTTX_MAX_MS]) cJSON_AddNumberToObject(j, "DTTX_MAX_MS", s_dwm_cfg.syn_dttx_max_ms);
    if (s_dwm_cfg.have[H_SYN_LOCK_NEED]) cJSON_AddNumberToObject(j, "LOCK_NEED", s_dwm_cfg.syn_lock_need);
    if (s_dwm_cfg.have[H_PHY_PLEN]) cJSON_AddNumberToObject(j, "PHY_PLEN", s_dwm_cfg.phy_plen);
    if (s_dwm_cfg.have[H_PHY_PAC]) cJSON_AddNumberToObject(j, "PHY_PAC", s_dwm_cfg.phy_pac);
    if (s_dwm_cfg.have[H_PHY_TX_CODE]) cJSON_AddNumberToObject(j, "PHY_TX_CODE", s_dwm_cfg.phy_tx_code);
    if (s_dwm_cfg.have[H_PHY_RX_CODE]) cJSON_AddNumberToObject(j, "PHY_RX_CODE", s_dwm_cfg.phy_rx_code);
    if (s_dwm_cfg.have[H_PHY_SFD]) cJSON_AddNumberToObject(j, "PHY_SFD", s_dwm_cfg.phy_sfd);
    if (s_dwm_cfg.have[H_PHY_BR]) cJSON_AddNumberToObject(j, "PHY_BR", s_dwm_cfg.phy_br);
    if (s_dwm_cfg.have[H_PHY_PHRMODE]) cJSON_AddNumberToObject(j, "PHY_PHRMODE", s_dwm_cfg.phy_phrmode);
    if (s_dwm_cfg.have[H_PHY_PHRRATE]) cJSON_AddNumberToObject(j, "PHY_PHRRATE", s_dwm_cfg.phy_phrrate);
    if (s_dwm_cfg.have[H_PHY_STS_MODE]) cJSON_AddNumberToObject(j, "PHY_STS_MODE", s_dwm_cfg.phy_sts_mode);
    if (s_dwm_cfg.have[H_PHY_STS_LEN]) cJSON_AddNumberToObject(j, "PHY_STS_LEN", s_dwm_cfg.phy_sts_len);
    if (s_dwm_cfg.have[H_PHY_PDOA]) cJSON_AddNumberToObject(j, "PHY_PDOA", s_dwm_cfg.phy_pdoa);
}

static bool parse_tlvs_and_update(const uint8_t *p, uint16_t n)
{
    bool changed = false;
    while (p && n >= 2) {
        uint8_t t = p[0];
        uint8_t l = p[1];
        p += 2;
        n -= 2;
        if (n < l) break;

        if (t == 0x00 && l >= 1) {
            uint8_t ver = p[0];
            if (ver == 1) s_tlv_section = 1;
            else if (ver == 2) s_tlv_section = 2;
            else s_tlv_section = 0;
            p += l;
            n -= l;
            continue;
        }

        if (s_tlv_section != 1) {
            p += l;
            n -= l;
            continue;
        }

        switch (t) {
            case 0x01: if (l == 1) { s_dwm_cfg.status = p[0]; s_dwm_cfg.have[H_STATUS] = true; changed = true; } break;
            case 0x02: if (l == 4) { s_dwm_cfg.uptime_ms = rd32be(p); s_dwm_cfg.have[H_UPTIME_MS] = true; changed = true; } break;
            case 0x03: if (l == 2) { s_dwm_cfg.sync_ms = rd16be(p); s_dwm_cfg.have[H_SYNC_MS] = true; changed = true; } break;
            case 0x10: if (l == 2) { s_dwm_cfg.network_id = rd16be(p); s_dwm_cfg.have[H_NETWORK_ID] = true; changed = true; } break;
            case 0x11: if (l == 2) { s_dwm_cfg.zone_id = rd16be(p); s_dwm_cfg.have[H_ZONE_ID] = true; changed = true; } break;
            case 0x12: if (l == 4) { s_dwm_cfg.anchor_id = rd32be(p); s_dwm_cfg.have[H_ANCHOR_ID] = true; changed = true; } break;
            case 0x20: if (l == 2) { s_dwm_cfg.hb_ms = rd16be(p); s_dwm_cfg.have[H_HB_MS] = true; changed = true; } break;
            case 0x1F: if (l == 1) { s_dwm_cfg.log_level = p[0]; s_dwm_cfg.have[H_LOG_LEVEL] = true; changed = true; } break;
            case 0x13: if (l == 4) { s_dwm_cfg.tx_ant_dly = (int32_t)rd32be(p); s_dwm_cfg.have[H_TX_ANT_DLY] = true; changed = true; } break;
            case 0x14: if (l == 4) { s_dwm_cfg.rx_ant_dly = (int32_t)rd32be(p); s_dwm_cfg.have[H_RX_ANT_DLY] = true; changed = true; } break;
            case 0x16: if (l == 4) { s_dwm_cfg.bias_ticks = (int32_t)rd32be(p); s_dwm_cfg.have[H_BIAS_TICKS] = true; changed = true; } break;
            case 0x40: if (l == 1) { s_dwm_cfg.phy_ch = p[0]; s_dwm_cfg.have[H_PHY_CH] = true; changed = true; } break;
            case 0x49: if (l == 2) { s_dwm_cfg.phy_sfdto = rd16be(p); s_dwm_cfg.have[H_PHY_SFDTO] = true; changed = true; } break;
            case 0x30: if (l == 2) { s_dwm_cfg.syn_ppm_max = rd16be(p); s_dwm_cfg.have[H_SYN_PPM_MAX] = true; changed = true; } break;
            case 0x31: if (l == 2) { s_dwm_cfg.syn_jump_ppm = rd16be(p); s_dwm_cfg.have[H_SYN_JUMP_PPM] = true; changed = true; } break;
            case 0x32: if (l == 2) { s_dwm_cfg.syn_ab_gap_ms = rd16be(p); s_dwm_cfg.have[H_SYN_AB_GAP_MS] = true; changed = true; } break;
            case 0x33: if (l == 1) { s_dwm_cfg.syn_ms_ewma_den = p[0]; s_dwm_cfg.have[H_SYN_MS_EWMA_DEN] = true; changed = true; } break;
            case 0x34: if (l == 1) { s_dwm_cfg.syn_tk_ewma_den = p[0]; s_dwm_cfg.have[H_SYN_TK_EWMA_DEN] = true; changed = true; } break;
            case 0x35: if (l == 2) { s_dwm_cfg.syn_tk_min_ms = rd16be(p); s_dwm_cfg.have[H_SYN_TK_MIN_MS] = true; changed = true; } break;
            case 0x36: if (l == 2) { s_dwm_cfg.syn_tk_max_ms = rd16be(p); s_dwm_cfg.have[H_SYN_TK_MAX_MS] = true; changed = true; } break;
            case 0x37: if (l == 2) { s_dwm_cfg.syn_dttx_min_ms = rd16be(p); s_dwm_cfg.have[H_SYN_DTTX_MIN_MS] = true; changed = true; } break;
            case 0x38: if (l == 2) { s_dwm_cfg.syn_dttx_max_ms = rd16be(p); s_dwm_cfg.have[H_SYN_DTTX_MAX_MS] = true; changed = true; } break;
            case 0x39: if (l == 1) { s_dwm_cfg.syn_lock_need = p[0]; s_dwm_cfg.have[H_SYN_LOCK_NEED] = true; changed = true; } break;
            case 0x41: if (l == 1) { s_dwm_cfg.phy_plen = p[0]; s_dwm_cfg.have[H_PHY_PLEN] = true; changed = true; } break;
            case 0x42: if (l == 1) { s_dwm_cfg.phy_pac = p[0]; s_dwm_cfg.have[H_PHY_PAC] = true; changed = true; } break;
            case 0x43: if (l == 1) { s_dwm_cfg.phy_tx_code = p[0]; s_dwm_cfg.have[H_PHY_TX_CODE] = true; changed = true; } break;
            case 0x44: if (l == 1) { s_dwm_cfg.phy_rx_code = p[0]; s_dwm_cfg.have[H_PHY_RX_CODE] = true; changed = true; } break;
            case 0x45: if (l == 1) { s_dwm_cfg.phy_sfd = p[0]; s_dwm_cfg.have[H_PHY_SFD] = true; changed = true; } break;
            case 0x46: if (l == 1) { s_dwm_cfg.phy_br = p[0]; s_dwm_cfg.have[H_PHY_BR] = true; changed = true; } break;
            case 0x47: if (l == 1) { s_dwm_cfg.phy_phrmode = p[0]; s_dwm_cfg.have[H_PHY_PHRMODE] = true; changed = true; } break;
            case 0x48: if (l == 1) { s_dwm_cfg.phy_phrrate = p[0]; s_dwm_cfg.have[H_PHY_PHRRATE] = true; changed = true; } break;
            case 0x4A: if (l == 1) { s_dwm_cfg.phy_sts_mode = p[0]; s_dwm_cfg.have[H_PHY_STS_MODE] = true; changed = true; } break;
            case 0x4B: if (l == 1) { s_dwm_cfg.phy_sts_len = p[0]; s_dwm_cfg.have[H_PHY_STS_LEN] = true; changed = true; } break;
            case 0x4C: if (l == 1) { s_dwm_cfg.phy_pdoa = p[0]; s_dwm_cfg.have[H_PHY_PDOA] = true; changed = true; } break;
            default: break;
        }
        p += l;
        n -= l;
    }
    return changed;
}

static void dwm_worker_task(void *arg)
{
    (void)arg;
    frame_t *f = NULL;
    for (;;) {
        if (xQueueReceive(s_dwm_q, &f, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        if (!f) continue;

        if (f->from_cfg && f->len >= 2) {
            uint8_t op = f->data[1];
            if (op == OP_START && f->len >= 6) {
                uint16_t req_id = rd16be(&f->data[2]);
                if (req_id == s_dwm_active_req_id) {
                    if (s_dwm_lock && xSemaphoreTake(s_dwm_lock, pdMS_TO_TICKS(1000)) == pdTRUE) {
                        s_tlv_section = 1;
                        s_dwm_last_line_tick = xTaskGetTickCount();
                        xSemaphoreGive(s_dwm_lock);
                    }
                    if (s_dwm_sem) xSemaphoreGive(s_dwm_sem);
                }
            } else if (op == OP_LINE && f->len >= 6) {
                uint16_t req_id = rd16be(&f->data[2]);
                if (req_id == s_dwm_active_req_id) {
                    if (s_dwm_lock && xSemaphoreTake(s_dwm_lock, pdMS_TO_TICKS(1000)) == pdTRUE) {
                        (void)parse_tlvs_and_update(f->data + 6, (uint16_t)(f->len - 6));
                        s_dwm_last_line_tick = xTaskGetTickCount();
                        s_dwm_last_refresh_tick = s_dwm_last_line_tick;
                        s_dwm_first_line_seen = true;
                        s_dwm_have_snapshot = dwm_has_any_data();
                        xSemaphoreGive(s_dwm_lock);
                    }
                    if (s_dwm_sem) xSemaphoreGive(s_dwm_sem);
                }
            } else if (op == OP_DONE && f->len >= 4) {
                uint16_t req_id = rd16be(&f->data[2]);
                if (req_id == s_dwm_active_req_id) {
                    if (s_dwm_lock && xSemaphoreTake(s_dwm_lock, pdMS_TO_TICKS(1000)) == pdTRUE) {
                        s_dwm_cfg_done = true;
                        s_dwm_refresh_in_progress = false;
                        s_dwm_last_refresh_tick = xTaskGetTickCount();
                        xSemaphoreGive(s_dwm_lock);
                    }
                    if (s_dwm_sem) xSemaphoreGive(s_dwm_sem);
                }
            }
        }

        free(f);
    }
}

void udp_config_on_ble_notify(const uint8_t *data, uint16_t len, bool from_cfg)
{
    if (!from_cfg || !data || len < 2 || !s_dwm_q) {
        return;
    }

    uint8_t op = data[1];
    if (op != OP_START && op != OP_LINE && op != OP_DONE) {
        return;
    }

    frame_t *f = (frame_t *)malloc(sizeof(frame_t) + len);
    if (!f) {
        return;
    }

    f->len = len;
    f->from_cfg = from_cfg;
    memcpy(f->data, data, len);

    if (xQueueSend(s_dwm_q, &f, pdMS_TO_TICKS(10)) != pdTRUE) {
        free(f);
    }
}

static void dwm_refresh_task(void *arg)
{
    (void)arg;
    const TickType_t hard_cap = pdMS_TO_TICKS(150000);
    const TickType_t idle_gap = pdMS_TO_TICKS(10000);

    for (;;) {
        (void)xSemaphoreTake(s_dwm_refresh_sem, portMAX_DELAY);

        if (!s_dwm_lock) {
            continue;
        }
        if (xSemaphoreTake(s_dwm_lock, pdMS_TO_TICKS(2000)) != pdTRUE) {
            continue;
        }

        bool should_start = !s_dwm_refresh_in_progress;
        if (should_start) {
            if (s_dwm_sem) {
                xSemaphoreTake(s_dwm_sem, 0);
            }
            drain_dwm_queue();
            s_dwm_cfg_done = false;
            s_dwm_first_line_seen = false;
            s_tlv_section = 1;
            s_dwm_active_req_id = ++s_dwm_req_id;
            s_dwm_refresh_in_progress = true;
            s_dwm_last_line_tick = xTaskGetTickCount();
        }
        xSemaphoreGive(s_dwm_lock);

        if (!should_start) {
            continue;
        }

        esp_err_t err = ble_send_get(s_dwm_active_req_id);
        if (err != ESP_OK) {
            if (xSemaphoreTake(s_dwm_lock, pdMS_TO_TICKS(1000)) == pdTRUE) {
                s_dwm_refresh_in_progress = false;
                xSemaphoreGive(s_dwm_lock);
            }
            ESP_LOGW(TAG, "background DWM refresh failed: %s", esp_err_to_name(err));
            continue;
        }

        TickType_t start = xTaskGetTickCount();
        for (;;) {
            if (s_dwm_sem) {
                (void)xSemaphoreTake(s_dwm_sem, pdMS_TO_TICKS(1000));
            } else {
                vTaskDelay(pdMS_TO_TICKS(1000));
            }

            if (xSemaphoreTake(s_dwm_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
                continue;
            }

            TickType_t now = xTaskGetTickCount();
            bool done = s_dwm_cfg_done;
            bool first_line = s_dwm_first_line_seen;
            bool timeout = (now - start) > hard_cap;
            bool idle = first_line && ((now - s_dwm_last_line_tick) > idle_gap);

            if (done || timeout || idle) {
                s_dwm_cfg_done = false;
                s_dwm_refresh_in_progress = false;
                xSemaphoreGive(s_dwm_lock);
                break;
            }

            xSemaphoreGive(s_dwm_lock);
        }
    }
}

static esp_err_t dwm_get_snapshot_json(char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return ESP_ERR_INVALID_ARG;
    if (!s_dwm_lock) return ESP_ERR_INVALID_STATE;

    TickType_t now = xTaskGetTickCount();
    if (!s_dwm_have_snapshot || !s_dwm_refresh_in_progress || ((now - s_dwm_last_refresh_tick) > pdMS_TO_TICKS(30000))) {
        dwm_request_refresh(!s_dwm_have_snapshot);
    }

    if (!s_dwm_have_snapshot && s_dwm_sem) {
        for (int i = 0; i < 5 && !s_dwm_have_snapshot; ++i) {
            (void)xSemaphoreTake(s_dwm_sem, pdMS_TO_TICKS(1000));
        }
    }

    if (xSemaphoreTake(s_dwm_lock, pdMS_TO_TICKS(1500)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    cJSON *obj = cJSON_CreateObject();
    char *printed = NULL;
    if (!obj) {
        xSemaphoreGive(s_dwm_lock);
        return ESP_ERR_NO_MEM;
    }

    build_dwm_json(obj);
    if (s_dwm_refresh_in_progress) {
        cJSON_AddBoolToObject(obj, "_refreshing", true);
    }
    printed = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);

    if (!printed) {
        xSemaphoreGive(s_dwm_lock);
        return ESP_ERR_NO_MEM;
    }

    if (strlen(printed) + 1 > out_sz) {
        free(printed);
        xSemaphoreGive(s_dwm_lock);
        return ESP_ERR_INVALID_SIZE;
    }

    strcpy(out, printed);
    free(printed);
    xSemaphoreGive(s_dwm_lock);
    return s_dwm_have_snapshot ? ESP_OK : ESP_ERR_TIMEOUT;
}

static esp_err_t dwm_set_from_json_obj(const cJSON *dwm_obj)
{
    if (!cJSON_IsObject(dwm_obj)) return ESP_ERR_INVALID_ARG;

    cJSON *dup = cJSON_Duplicate((cJSON *)dwm_obj, 1);
    if (!dup) return ESP_ERR_NO_MEM;

    esp_err_t err = uwb_cfg_cli_set_from_json(dup, ++s_dwm_req_id);
    cJSON_Delete(dup);

    if (err == ESP_OK) {
        dwm_request_refresh(true);
    }
    return err;
}

static esp_err_t add_full_system_snapshot(cJSON *resp)
{
    cJSON *system = build_system_json_obj();
    cJSON *ble = build_ble_json_obj();
    cJSON *wifi = build_wifi_json_obj();

    if (!system || !ble || !wifi) {
        if (system) cJSON_Delete(system);
        if (ble) cJSON_Delete(ble);
        if (wifi) cJSON_Delete(wifi);
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddItemToObject(resp, "system", system);
    cJSON_AddItemToObject(resp, "ble", ble);
    cJSON_AddItemToObject(resp, "wifi", wifi);
    return ESP_OK;
}

static esp_err_t response_from_json(cJSON *resp_root, char *out, size_t out_sz)
{
    char *printed;
    if (!resp_root || !out || out_sz == 0) return ESP_ERR_INVALID_ARG;

    printed = cJSON_PrintUnformatted(resp_root);
    if (!printed) return ESP_ERR_NO_MEM;

    if (strlen(printed) + 1 > out_sz) {
        free(printed);
        return ESP_ERR_INVALID_SIZE;
    }

    strcpy(out, printed);
    free(printed);
    return ESP_OK;
}

static esp_err_t handle_get_command(const char *target, char *out, size_t out_sz)
{
    cJSON *resp = cJSON_CreateObject();
    esp_err_t err = ESP_OK;

    if (!resp) return ESP_ERR_NO_MEM;

    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddStringToObject(resp, "cmd", "get");
    cJSON_AddStringToObject(resp, "target", target ? target : "all");
    cJSON_AddNumberToObject(resp, "listen_port", NET.udp_port ? NET.udp_port : UDP_CONFIG_DEFAULT_PORT);

    if (!target || strcmp(target, "all") == 0 || strcmp(target, "system") == 0 || strcmp(target, "ble") == 0 || strcmp(target, "wifi") == 0) {
        err = add_full_system_snapshot(resp);
        if (err != ESP_OK) goto done;
    }

    if ((target && strcmp(target, "dwm") == 0) || (!target || strcmp(target, "all") == 0)) {
        dwm_request_refresh(false);
    }

    if (target && strcmp(target, "dwm") == 0) {
        char *dwm_buf = (char *)calloc(1, 4096);
        if (!dwm_buf) {
            err = ESP_ERR_NO_MEM;
            goto done;
        }
        err = dwm_get_snapshot_json(dwm_buf, 4096);
        if (err == ESP_OK) {
            cJSON *dwm = cJSON_Parse(dwm_buf);
            if (dwm) cJSON_AddItemToObject(resp, "dwm", dwm);
        } else {
            cJSON_ReplaceItemInObject(resp, "ok", cJSON_CreateBool(false));
            cJSON_AddStringToObject(resp, "error", esp_err_to_name(err));
        }
        free(dwm_buf);
    } else if (!target || strcmp(target, "all") == 0) {
        char *dwm_buf = (char *)calloc(1, 4096);
        if (!dwm_buf) {
            err = ESP_ERR_NO_MEM;
            goto done;
        }
        err = dwm_get_snapshot_json(dwm_buf, 4096);
        if (err == ESP_OK) {
            cJSON *dwm = cJSON_Parse(dwm_buf);
            if (dwm) cJSON_AddItemToObject(resp, "dwm", dwm);
        } else {
            cJSON_AddStringToObject(resp, "dwm_error", esp_err_to_name(err));
        }
        free(dwm_buf);
    }

    err = response_from_json(resp, out, out_sz);

done:
    cJSON_Delete(resp);
    return err;
}

static esp_err_t handle_set_command(const cJSON *root, const char *target, char *out, size_t out_sz)
{
    esp_err_t err = ESP_OK;
    const cJSON *system_obj = obj_get(root, "system");
    const cJSON *ble_obj = obj_get(root, "ble");
    const cJSON *wifi_obj = obj_get(root, "wifi");
    const cJSON *dwm_obj = obj_get(root, "dwm");
    cJSON *resp = cJSON_CreateObject();

    if (!resp) return ESP_ERR_NO_MEM;

    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddStringToObject(resp, "cmd", "set");
    cJSON_AddStringToObject(resp, "target", target ? target : "all");

    if (!target || strcmp(target, "all") == 0 || strcmp(target, "system") == 0 || strcmp(target, "ble") == 0 || strcmp(target, "wifi") == 0) {
        if (system_obj) {
            err = system_apply_from_json(system_obj);
            if (err != ESP_OK) goto fail;
        }
        if (ble_obj) {
            err = ble_apply_from_json(ble_obj);
            if (err != ESP_OK) goto fail;
        }
        if (wifi_obj) {
            err = wifi_apply_from_json(wifi_obj);
            if (err != ESP_OK) goto fail;
        }
    }

    if ((target && strcmp(target, "dwm") == 0) || (!target || strcmp(target, "all") == 0)) {
        if (dwm_obj) {
            err = dwm_set_from_json_obj(dwm_obj);
            if (err != ESP_OK) goto fail;
            cJSON_AddBoolToObject(resp, "dwm_sent", true);
        }
    }

    err = add_full_system_snapshot(resp);
    if (err != ESP_OK) goto fail;

    if (dwm_obj) {
        cJSON_AddNumberToObject(resp, "dwm_request_id", s_dwm_req_id);
    }

    err = response_from_json(resp, out, out_sz);
    cJSON_Delete(resp);
    return err;

fail:
    cJSON_ReplaceItemInObject(resp, "ok", cJSON_CreateBool(false));
    cJSON_AddStringToObject(resp, "error", esp_err_to_name(err));
    (void)response_from_json(resp, out, out_sz);
    cJSON_Delete(resp);
    return err;
}

static esp_err_t handle_udp_request(const char *req, char *resp, size_t resp_sz)
{
    cJSON *root;
    const cJSON *cmd_item;
    const cJSON *target_item;
    const char *cmd = "get";
    const char *target = "all";

    if (!req || !resp || resp_sz == 0) return ESP_ERR_INVALID_ARG;

    root = cJSON_Parse(req);
    if (!root) {
        snprintf(resp, resp_sz, "{\"ok\":false,\"error\":\"invalid_json\"}");
        return ESP_ERR_INVALID_ARG;
    }

    cmd_item = obj_get(root, "cmd");
    target_item = obj_get(root, "target");
    if (cJSON_IsString(cmd_item) && cmd_item->valuestring) cmd = cmd_item->valuestring;
    if (cJSON_IsString(target_item) && target_item->valuestring) target = target_item->valuestring;

    esp_err_t err = validate_udp_auth(root);
    if (err != ESP_OK) {
        const char *reason = "invalid_auth";
        if (err == ESP_ERR_INVALID_ARG) {
            reason = "auth_required";
        } else if (err == ESP_ERR_NOT_FOUND) {
            reason = "auth_not_configured";
        }

        snprintf(resp, resp_sz,
                 "{\"ok\":false,\"cmd\":\"%s\",\"target\":\"%s\",\"error\":\"%s\"}",
                 cmd ? cmd : "", target ? target : "", reason);
        cJSON_Delete(root);
        return err;
    }

    if (strcmp(cmd, "ping") == 0) {
        snprintf(resp, resp_sz,
                 "{\"ok\":true,\"cmd\":\"ping\",\"pong\":true,\"listen_port\":%u}",
                 (unsigned)(NET.udp_port ? NET.udp_port : UDP_CONFIG_DEFAULT_PORT));
        err = ESP_OK;
    } else if (strcmp(cmd, "get") == 0) {
        err = handle_get_command(target, resp, resp_sz);
    } else if (strcmp(cmd, "set") == 0) {
        err = handle_set_command(root, target, resp, resp_sz);
    } else {
        snprintf(resp, resp_sz, "{\"ok\":false,\"error\":\"unsupported_cmd\"}");
        err = ESP_ERR_NOT_SUPPORTED;
    }

    cJSON_Delete(root);
    return err;
}

static void udp_socket_task(void *arg)
{
    (void)arg;
    int sock = -1;
    uint16_t bound_port = 0;
    const size_t rx_buf_sz = 2048;
    const size_t tx_buf_sz = 4096;
    char *rx_buf = (char *)malloc(rx_buf_sz);
    char *tx_buf = (char *)malloc(tx_buf_sz);

    if (!rx_buf || !tx_buf) {
        ESP_LOGE(TAG, "UDP config buffer alloc failed");
        free(rx_buf);
        free(tx_buf);
        vTaskDelete(NULL);
        return;
    }

    for (;;) {
        uint16_t desired_port = NET.udp_port ? NET.udp_port : UDP_CONFIG_DEFAULT_PORT;

        if (sock < 0 || desired_port != bound_port) {
            if (sock >= 0) {
                close(sock);
                sock = -1;
            }

            sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
            if (sock < 0) {
                ESP_LOGE(TAG, "socket failed");
                vTaskDelay(pdMS_TO_TICKS(1000));
                continue;
            }

            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(desired_port);

            int reuse = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

            if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                ESP_LOGE(TAG, "bind failed on port %u", (unsigned)desired_port);
                close(sock);
                sock = -1;
                vTaskDelay(pdMS_TO_TICKS(1000));
                continue;
            }

            bound_port = desired_port;
            ESP_LOGI(TAG, "UDP config listener bound on %u", (unsigned)bound_port);
        }

        struct sockaddr_in src_addr;
        socklen_t src_len = sizeof(src_addr);
        int len = recvfrom(sock, rx_buf, (int)(rx_buf_sz - 1), 0, (struct sockaddr *)&src_addr, &src_len);
        if (len < 0) {
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        rx_buf[len] = 0;
        (void)handle_udp_request(rx_buf, tx_buf, tx_buf_sz);
        (void)sendto(sock, tx_buf, strlen(tx_buf), 0, (struct sockaddr *)&src_addr, src_len);
    }
}

esp_err_t udp_config_server_start(void)
{
    if (s_udp_task_started) {
        return ESP_OK;
    }

    if (!s_dwm_q) s_dwm_q = xQueueCreate(8, sizeof(frame_t *));
    if (!s_dwm_sem) s_dwm_sem = xSemaphoreCreateBinary();
    if (!s_dwm_lock) s_dwm_lock = xSemaphoreCreateMutex();
    if (!s_dwm_refresh_sem) s_dwm_refresh_sem = xSemaphoreCreateBinary();

    if (!s_dwm_q || !s_dwm_sem || !s_dwm_lock || !s_dwm_refresh_sem) {
        return ESP_ERR_NO_MEM;
    }

    if (!s_dwm_worker) {
        if (xTaskCreatePinnedToCore(dwm_worker_task, "udp_dwm_worker", 4096, NULL, 5, &s_dwm_worker, tskNO_AFFINITY) != pdPASS) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (!s_dwm_refresh_task_handle) {
        if (xTaskCreatePinnedToCore(dwm_refresh_task, "udp_dwm_refresh", 4096, NULL, 5, &s_dwm_refresh_task_handle, tskNO_AFFINITY) != pdPASS) {
            return ESP_ERR_NO_MEM;
        }
    }

    restore_telemetry_runtime();

    if (!s_hb_task_handle) {
        if (xTaskCreate(telemetry_hb_task, "udp_hb", 4096, NULL, 4, &s_hb_task_handle) != pdPASS) {
            return ESP_ERR_NO_MEM;
        }
    }

    TaskHandle_t sock_task = NULL;
    if (xTaskCreate(udp_socket_task, "udp_cfg_sock", 9216, NULL, 5, &sock_task) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }

    s_udp_task_started = true;

    char auth_buf[128] = {0};
    if (load_udp_auth_secret(auth_buf, sizeof(auth_buf)) == ESP_OK) {
        ESP_LOGI(TAG, "UDP auth is required for every request");
    } else {
        ESP_LOGW(TAG, "UDP auth secret is not configured yet");
    }

    return ESP_OK;
}
