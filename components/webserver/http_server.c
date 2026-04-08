// components/webserver/http_server.c
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "esp_http_server.h"
#include "esp_log.h"

#include "cJSON.h"
#include "ble.h"
#include "uwb_cfg_cli.h"
#include "hb_status.h"
#include "wifi_manager.h"
#include "ethernet.h"

/* ====== Általános ====== */
static const char* TAG = "HTTP_BRIDGE";

/* Egy kérés sorosítása mindenki számára */
static SemaphoreHandle_t s_ble_lock;
static SemaphoreHandle_t s_sem_ack;
static SemaphoreHandle_t s_sem_tlv;

/* GET ciklus állapot */
static uint16_t s_last_req = 0;
static volatile bool s_cfg_done = false;
static volatile TickType_t s_last_line_tick = 0;

/* BLE → feldolgozó sor (callbackben csak ide írunk) */
typedef struct {
    uint16_t len;
    bool     from_cfg;
    uint8_t  data[];
} frame_t;

static QueueHandle_t   s_q;
static TaskHandle_t    s_worker;

/* ====== Segédek ====== */
static inline uint16_t rd16be(const uint8_t* p){ return ((uint16_t)p[0] << 8) | p[1]; }
static inline uint32_t rd32be(const uint8_t* p){ return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static inline void log_set_u(const char* k, unsigned v){ ESP_LOGI(TAG,"%s=%u", k, v); }
static inline void log_set_i(const char* k, int v){ ESP_LOGI(TAG,"%s=%d", k, v); }

/* ====== Az aktuális, összeálló konfiguráció ====== */
enum {
    H_NETWORK_ID=0, H_ZONE_ID, H_ANCHOR_ID, H_HB_MS, H_LOG_LEVEL,
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
} s_cfg;

static void build_cfg_json(cJSON *j)
{
    if (s_cfg.have[H_STATUS])
        cJSON_AddNumberToObject(j, "STATUS", s_cfg.status);
    if (s_cfg.have[H_UPTIME_MS])
        cJSON_AddNumberToObject(j, "UPTIME_MS", s_cfg.uptime_ms);
    if (s_cfg.have[H_SYNC_MS])
        cJSON_AddNumberToObject(j, "SYNC_MS", s_cfg.sync_ms);

    if (s_cfg.have[H_NETWORK_ID])
        cJSON_AddNumberToObject(j, "NETWORK_ID", s_cfg.network_id);

    if (s_cfg.have[H_ZONE_ID]) {
        cJSON_AddNumberToObject(j, "ZONE_ID", s_cfg.zone_id);

        char hex[8];
        snprintf(hex, sizeof hex, "0x%04X", s_cfg.zone_id);
        cJSON_AddStringToObject(j, "ZONE_ID_HEX", hex);
    }

    if (s_cfg.have[H_ANCHOR_ID]) {
        char hex[11];
        snprintf(hex, sizeof hex, "0x%08" PRIX32, (uint32_t)s_cfg.anchor_id);
        cJSON_AddStringToObject(j, "ANCHOR_ID", hex);
    }

    if (s_cfg.have[H_HB_MS])
        cJSON_AddNumberToObject(j, "HB_MS", s_cfg.hb_ms);
    if (s_cfg.have[H_LOG_LEVEL])
        cJSON_AddNumberToObject(j, "LOG_LEVEL", s_cfg.log_level);
    if (s_cfg.have[H_TX_ANT_DLY])
        cJSON_AddNumberToObject(j, "TX_ANT_DLY", s_cfg.tx_ant_dly);
    if (s_cfg.have[H_RX_ANT_DLY])
        cJSON_AddNumberToObject(j, "RX_ANT_DLY", s_cfg.rx_ant_dly);
    if (s_cfg.have[H_BIAS_TICKS])
        cJSON_AddNumberToObject(j, "BIAS_TICKS", s_cfg.bias_ticks);
    if (s_cfg.have[H_PHY_CH])
        cJSON_AddNumberToObject(j, "PHY_CH", s_cfg.phy_ch);
    if (s_cfg.have[H_PHY_SFDTO])
        cJSON_AddNumberToObject(j, "PHY_SFDTO", s_cfg.phy_sfdto);

    if (s_cfg.have[H_SYN_PPM_MAX])
        cJSON_AddNumberToObject(j, "PPM_MAX", s_cfg.syn_ppm_max);
    if (s_cfg.have[H_SYN_JUMP_PPM])
        cJSON_AddNumberToObject(j, "JUMP_PPM", s_cfg.syn_jump_ppm);
    if (s_cfg.have[H_SYN_AB_GAP_MS])
        cJSON_AddNumberToObject(j, "AB_GAP_MS", s_cfg.syn_ab_gap_ms);
    if (s_cfg.have[H_SYN_MS_EWMA_DEN])
        cJSON_AddNumberToObject(j, "MS_EWMA_DEN", s_cfg.syn_ms_ewma_den);
    if (s_cfg.have[H_SYN_TK_EWMA_DEN])
        cJSON_AddNumberToObject(j, "TK_EWMA_DEN", s_cfg.syn_tk_ewma_den);
    if (s_cfg.have[H_SYN_TK_MIN_MS])
        cJSON_AddNumberToObject(j, "TK_MIN_MS", s_cfg.syn_tk_min_ms);
    if (s_cfg.have[H_SYN_TK_MAX_MS])
        cJSON_AddNumberToObject(j, "TK_MAX_MS", s_cfg.syn_tk_max_ms);
    if (s_cfg.have[H_SYN_DTTX_MIN_MS])
        cJSON_AddNumberToObject(j, "DTTX_MIN_MS", s_cfg.syn_dttx_min_ms);
    if (s_cfg.have[H_SYN_DTTX_MAX_MS])
        cJSON_AddNumberToObject(j, "DTTX_MAX_MS", s_cfg.syn_dttx_max_ms);
    if (s_cfg.have[H_SYN_LOCK_NEED])
        cJSON_AddNumberToObject(j, "LOCK_NEED", s_cfg.syn_lock_need);

    if (s_cfg.have[H_PHY_PLEN])
        cJSON_AddNumberToObject(j, "PHY_PLEN", s_cfg.phy_plen);
    if (s_cfg.have[H_PHY_PAC])
        cJSON_AddNumberToObject(j, "PHY_PAC", s_cfg.phy_pac);
    if (s_cfg.have[H_PHY_TX_CODE])
        cJSON_AddNumberToObject(j, "PHY_TX_CODE", s_cfg.phy_tx_code);
    if (s_cfg.have[H_PHY_RX_CODE])
        cJSON_AddNumberToObject(j, "PHY_RX_CODE", s_cfg.phy_rx_code);
    if (s_cfg.have[H_PHY_SFD])
        cJSON_AddNumberToObject(j, "PHY_SFD", s_cfg.phy_sfd);
    if (s_cfg.have[H_PHY_BR])
        cJSON_AddNumberToObject(j, "PHY_BR", s_cfg.phy_br);
    if (s_cfg.have[H_PHY_PHRMODE])
        cJSON_AddNumberToObject(j, "PHY_PHRMODE", s_cfg.phy_phrmode);
    if (s_cfg.have[H_PHY_PHRRATE])
        cJSON_AddNumberToObject(j, "PHY_PHRRATE", s_cfg.phy_phrrate);
    if (s_cfg.have[H_PHY_STS_MODE])
        cJSON_AddNumberToObject(j, "PHY_STS_MODE", s_cfg.phy_sts_mode);
    if (s_cfg.have[H_PHY_STS_LEN])
        cJSON_AddNumberToObject(j, "PHY_STS_LEN", s_cfg.phy_sts_len);
    if (s_cfg.have[H_PHY_PDOA])
        cJSON_AddNumberToObject(j, "PHY_PDOA", s_cfg.phy_pdoa);
}

static void reset_cfg(void)
{
    memset(&s_cfg, 0, sizeof(s_cfg));
}

static uint8_t s_tlv_section = 1;

/*
 * A régi, fix pozíciós HB parser itt hibás volt: túl rövid minimum hosszal
 * olvasott a p[16] byte-ig, miközben a jelenlegi HB források nem ezt a fix
 * bináris layoutot használják. Meghagyjuk no-opként kompatibilitási okból,
 * de nem frissítünk belőle állapotot.
 */
static void try_parse_hb_line(const uint8_t *p, uint16_t n)
{
    (void)p;
    (void)n;
}

static bool parse_tlvs_and_update(const uint8_t* p, uint16_t n)
{
    if (!p || n < 2) return false;
    bool changed = false;

    while (n >= 2) {
        uint8_t t = p[0], l = p[1];
        p += 2; n -= 2;
        if (n < l) break;

        if (t == 0x00 && l >= 1) {
            uint8_t ver = p[0];
            if      (ver == 1) s_tlv_section = 1;
            else if (ver == 2) s_tlv_section = 2;
            else               s_tlv_section = 0;

            p += l;
            n -= l;
            continue;
        }

        if (s_tlv_section != 1) {
            p += l;
            n -= l;
            continue;
        }

        switch(t){
            case 0x01: if (l==1) { s_cfg.status    = p[0]; s_cfg.have[H_STATUS]=true; changed=true; log_set_u("STATUS", s_cfg.status); } break;
            case 0x02: if (l==4) { s_cfg.uptime_ms = rd32be(p); s_cfg.have[H_UPTIME_MS]=true; changed=true; log_set_u("UPTIME_MS", s_cfg.uptime_ms); } break;
            case 0x03: if (l==2) { s_cfg.sync_ms   = rd16be(p); s_cfg.have[H_SYNC_MS]=true; changed=true; log_set_u("SYNC_MS", s_cfg.sync_ms); } break;
            case 0x10: if(l==2){ s_cfg.network_id = rd16be(p); s_cfg.have[H_NETWORK_ID]=true; changed=true; log_set_u("NETWORK_ID", s_cfg.network_id); } break;
            case 0x11: if(l==2){ s_cfg.zone_id    = rd16be(p); s_cfg.have[H_ZONE_ID]=true;    changed=true; log_set_u("ZONE_ID", s_cfg.zone_id); } break;
            case 0x12: if(l==4){ s_cfg.anchor_id  = rd32be(p); s_cfg.have[H_ANCHOR_ID]=true;   changed=true; ESP_LOGI(TAG,"ANCHOR_ID=0x%08" PRIX32, s_cfg.anchor_id); } break;
            case 0x20: if(l==2){ s_cfg.hb_ms      = rd16be(p); s_cfg.have[H_HB_MS]=true;       changed=true; log_set_u("HB_MS", s_cfg.hb_ms); } break;
            case 0x1F: if(l==1){ s_cfg.log_level  = p[0];      s_cfg.have[H_LOG_LEVEL]=true;   changed=true; log_set_u("LOG_LEVEL", s_cfg.log_level); } break;
            case 0x13: if(l==4){ s_cfg.tx_ant_dly = (int32_t)rd32be(p); s_cfg.have[H_TX_ANT_DLY]=true; changed=true; log_set_i("TX_ANT_DLY", s_cfg.tx_ant_dly); } break;
            case 0x14: if(l==4){ s_cfg.rx_ant_dly = (int32_t)rd32be(p); s_cfg.have[H_RX_ANT_DLY]=true; changed=true; log_set_i("RX_ANT_DLY", s_cfg.rx_ant_dly); } break;
            case 0x16: if(l==4){ s_cfg.bias_ticks = (int32_t)rd32be(p); s_cfg.have[H_BIAS_TICKS]=true; changed=true; log_set_i("BIAS_TICKS", s_cfg.bias_ticks); } break;
            case 0x40: if(l==1){ s_cfg.phy_ch     = p[0];      s_cfg.have[H_PHY_CH]=true;      changed=true; log_set_u("PHY_CH", s_cfg.phy_ch); } break;
            case 0x49: if(l==2){ s_cfg.phy_sfdto  = rd16be(p); s_cfg.have[H_PHY_SFDTO]=true;   changed=true; log_set_u("PHY_SFDTO", s_cfg.phy_sfdto); } break;

            case 0x30: if(l==2){ s_cfg.syn_ppm_max   = rd16be(p); s_cfg.have[H_SYN_PPM_MAX]=true;   changed=true; log_set_u("PPM_MAX", s_cfg.syn_ppm_max); } break;
            case 0x31: if(l==2){ s_cfg.syn_jump_ppm  = rd16be(p); s_cfg.have[H_SYN_JUMP_PPM]=true;  changed=true; log_set_u("JUMP_PPM", s_cfg.syn_jump_ppm); } break;
            case 0x32: if(l==2){ s_cfg.syn_ab_gap_ms = rd16be(p); s_cfg.have[H_SYN_AB_GAP_MS]=true; changed=true; log_set_u("AB_GAP_MS", s_cfg.syn_ab_gap_ms); } break;
            case 0x33: if(l==1){ s_cfg.syn_ms_ewma_den= p[0];     s_cfg.have[H_SYN_MS_EWMA_DEN]=true; changed=true; log_set_u("MS_EWMA_DEN", s_cfg.syn_ms_ewma_den); } break;
            case 0x34: if(l==1){ s_cfg.syn_tk_ewma_den= p[0];     s_cfg.have[H_SYN_TK_EWMA_DEN]=true; changed=true; log_set_u("TK_EWMA_DEN", s_cfg.syn_tk_ewma_den); } break;
            case 0x35: if(l==2){ s_cfg.syn_tk_min_ms = rd16be(p); s_cfg.have[H_SYN_TK_MIN_MS]=true;  changed=true; log_set_u("TK_MIN_MS", s_cfg.syn_tk_min_ms); } break;
            case 0x36: if(l==2){ s_cfg.syn_tk_max_ms = rd16be(p); s_cfg.have[H_SYN_TK_MAX_MS]=true;  changed=true; log_set_u("TK_MAX_MS", s_cfg.syn_tk_max_ms); } break;
            case 0x37: if(l==2){ s_cfg.syn_dttx_min_ms=rd16be(p); s_cfg.have[H_SYN_DTTX_MIN_MS]=true; changed=true; log_set_u("DTTX_MIN_MS", s_cfg.syn_dttx_min_ms); } break;
            case 0x38: if(l==2){ s_cfg.syn_dttx_max_ms=rd16be(p); s_cfg.have[H_SYN_DTTX_MAX_MS]=true; changed=true; log_set_u("DTTX_MAX_MS", s_cfg.syn_dttx_max_ms); } break;
            case 0x39: if(l==1){ s_cfg.syn_lock_need = p[0];      s_cfg.have[H_SYN_LOCK_NEED]=true;   changed=true; log_set_u("LOCK_NEED", s_cfg.syn_lock_need); } break;

            case 0x41: if(l==1){ s_cfg.phy_plen    = p[0]; s_cfg.have[H_PHY_PLEN]=true;    changed=true; log_set_u("PHY_PLEN", s_cfg.phy_plen); } break;
            case 0x42: if(l==1){ s_cfg.phy_pac     = p[0]; s_cfg.have[H_PHY_PAC]=true;     changed=true; log_set_u("PHY_PAC", s_cfg.phy_pac); } break;
            case 0x43: if(l==1){ s_cfg.phy_tx_code = p[0]; s_cfg.have[H_PHY_TX_CODE]=true; changed=true; log_set_u("PHY_TX_CODE", s_cfg.phy_tx_code); } break;
            case 0x44: if(l==1){ s_cfg.phy_rx_code = p[0]; s_cfg.have[H_PHY_RX_CODE]=true; changed=true; log_set_u("PHY_RX_CODE", s_cfg.phy_rx_code); } break;
            case 0x45: if(l==1){ s_cfg.phy_sfd     = p[0]; s_cfg.have[H_PHY_SFD]=true;     changed=true; log_set_u("PHY_SFD", s_cfg.phy_sfd); } break;
            case 0x46: if(l==1){ s_cfg.phy_br      = p[0]; s_cfg.have[H_PHY_BR]=true;      changed=true; log_set_u("PHY_BR", s_cfg.phy_br); } break;
            case 0x47: if(l==1){ s_cfg.phy_phrmode = p[0]; s_cfg.have[H_PHY_PHRMODE]=true; changed=true; log_set_u("PHY_PHRMODE", s_cfg.phy_phrmode); } break;
            case 0x48: if(l==1){ s_cfg.phy_phrrate = p[0]; s_cfg.have[H_PHY_PHRRATE]=true; changed=true; log_set_u("PHY_PHRRATE", s_cfg.phy_phrrate); } break;
            case 0x4A: if(l==1){ s_cfg.phy_sts_mode= p[0]; s_cfg.have[H_PHY_STS_MODE]=true;changed=true; log_set_u("PHY_STS_MODE", s_cfg.phy_sts_mode); } break;
            case 0x4B: if(l==1){ s_cfg.phy_sts_len = p[0]; s_cfg.have[H_PHY_STS_LEN]=true; changed=true; log_set_u("PHY_STS_LEN", s_cfg.phy_sts_len); } break;
            case 0x4C: if(l==1){ s_cfg.phy_pdoa    = p[0]; s_cfg.have[H_PHY_PDOA]=true;    changed=true; log_set_u("PHY_PDOA", s_cfg.phy_pdoa); } break;
            default: break;
        }
        p += l; n -= l;
    }
    return changed;
}

static void on_ble_notify(const uint8_t* p, uint16_t n, bool from_cfg)
{
    if (!p || n == 0) return;

    if (n == 6 && p[0] == 1 && p[1] == 0x81) {
        if (s_sem_ack) xSemaphoreGive(s_sem_ack);
        return;
    }

    if (!s_q) return;

    bool is_tlv = (n >= 2 && (p[1] == OP_START || p[1] == OP_LINE || p[1] == OP_DONE));

    if (!is_tlv) {
        try_parse_hb_line(p, n);
    }

    uint8_t op = is_tlv ? p[1] : 0;

    frame_t* f = (frame_t*)pvPortMalloc(sizeof(frame_t) + n);
    if (!f) {
        ESP_LOGW(TAG, "malloc fail in notify");
        return;
    }
    f->len = n;
    f->from_cfg = from_cfg;
    memcpy(f->data, p, n);

    if (xQueueSend(s_q, &f, pdMS_TO_TICKS(50)) != pdTRUE) {
        vPortFree(f);
        ESP_LOGW(TAG, "queue full, dropped TLV");
        return;
    }

    if (is_tlv && (op == OP_START || op == OP_LINE || op == OP_DONE)) {
        if (s_sem_tlv) xSemaphoreGive(s_sem_tlv);
    }
    else if (op == OP_DONE) {
        s_cfg_done = true;
        if (s_sem_tlv) xSemaphoreGive(s_sem_tlv);
    }
}

static void tlv_worker_task(void* arg)
{
    frame_t* f=NULL;
    for(;;){
        if(xQueueReceive(s_q,&f,portMAX_DELAY)!=pdTRUE) continue;
        if(!f) continue;

        if (f->len >= 2) {
            uint8_t op = f->data[1];
            if (op == OP_START) {
                s_last_line_tick = xTaskGetTickCount();
            } else if (op == OP_LINE && f->len >= 6) {
                const uint8_t* tlv = f->data + 6;
                uint16_t tlv_len = (uint16_t)(f->len - 6);
                (void)parse_tlvs_and_update(tlv, tlv_len);
                s_last_line_tick = xTaskGetTickCount();
            } else if (op == OP_DONE) {
                s_cfg_done = true;
            }
        }
        vPortFree(f);
    }
}

static void drain_queue(void){
    frame_t* f=NULL;
    while(xQueueReceive(s_q, &f, 0)==pdTRUE){
        if(f) vPortFree(f);
    }
}

static esp_err_t handle_dwm_set(httpd_req_t *req)
{
    int len = req->content_len;
    if (len <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "empty body");
        return ESP_OK;
    }

    char *buf = malloc(len + 1);
    if (!buf) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "no mem");
        return ESP_OK;
    }

    int off = 0;
    while (off < len) {
        int r = httpd_req_recv(req, buf + off, len - off);
        if (r <= 0) {
            free(buf);
            httpd_resp_set_status(req, "500 Internal Server Error");
            httpd_resp_sendstr(req, "recv error");
            return ESP_OK;
        }
        off += r;
    }
    buf[off] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        free(buf);
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "invalid JSON");
        return ESP_OK;
    }

    static uint16_t s_req_id = 1;
    uint16_t req_id = s_req_id++;

    esp_err_t er = uwb_cfg_cli_set_from_json(root, req_id);
    cJSON_Delete(root);
    free(buf);

    if (er != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "uwb_cfg_cli_set_from_json failed");
        return ESP_OK;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t dwm_get_handler(httpd_req_t* req)
{
    if(!s_ble_lock) s_ble_lock = xSemaphoreCreateMutex();
    xSemaphoreTake(s_ble_lock, portMAX_DELAY);

    if(!s_sem_tlv) s_sem_tlv = xSemaphoreCreateBinary();

    reset_cfg();
    drain_queue();
    xSemaphoreTake(s_sem_tlv, 0);
    s_cfg_done=false;
    s_last_line_tick = xTaskGetTickCount();

    esp_err_t er = ble_send_get(++s_last_req);
    ESP_LOGI(TAG, "ble_send_get rc=0x%x", er);
    if (er != ESP_OK) {
        httpd_resp_set_status(req, "503 Service Unavailable");
        httpd_resp_sendstr(req, "");
        xSemaphoreGive(s_ble_lock);
        return ESP_FAIL;
    }

    if(xSemaphoreTake(s_sem_tlv, pdMS_TO_TICKS(60000)) != pdTRUE){
        httpd_resp_set_status(req, "504 Gateway Timeout");
        httpd_resp_sendstr(req, "");
        xSemaphoreGive(s_ble_lock);
        return ESP_FAIL;
    }

    TickType_t t0 = xTaskGetTickCount();
    const TickType_t HARD_CAP = pdMS_TO_TICKS(60000);
    const TickType_t IDLE_GAP = pdMS_TO_TICKS(500);

    for(;;){
        if (s_cfg_done) break;
        TickType_t now = xTaskGetTickCount();
        if (now - t0 > HARD_CAP) break;
        if (now - s_last_line_tick > IDLE_GAP) break;
        (void)xSemaphoreTake(s_sem_tlv, pdMS_TO_TICKS(200));
    }

    cJSON* j = cJSON_CreateObject();
    build_cfg_json(j);

    char* out = cJSON_PrintUnformatted(j);
    httpd_resp_set_type(req,"application/json");
    httpd_resp_sendstr(req, out ? out : "{}");
    if(out) free(out);
    cJSON_Delete(j);

    xSemaphoreGive(s_ble_lock);
    return ESP_OK;
}

static esp_err_t dwm_last_handler(httpd_req_t* req)
{
    if(!s_ble_lock) s_ble_lock = xSemaphoreCreateMutex();
    xSemaphoreTake(s_ble_lock, portMAX_DELAY);

    cJSON* j = cJSON_CreateObject();
    build_cfg_json(j);

    char* out = cJSON_PrintUnformatted(j);
    httpd_resp_set_type(req,"application/json");
    httpd_resp_sendstr(req, out ? out : "{}");
    if(out) free(out);
    cJSON_Delete(j);

    xSemaphoreGive(s_ble_lock);
    return ESP_OK;
}

/* ===== Wi-Fi config HTTP ===== */

static void json_add_string(cJSON *obj, const char *key, const char *value)
{
    cJSON_AddStringToObject(obj, key, value ? value : "");
}

static void json_copy_string(cJSON *obj, const char *key, char *out, size_t out_sz)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(item) || !item->valuestring || out_sz == 0) return;
    strncpy(out, item->valuestring, out_sz - 1);
    out[out_sz - 1] = 0;
}

static void json_copy_u8(cJSON *obj, const char *key, uint8_t *out)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsBool(item)) {
        *out = cJSON_IsTrue(item) ? 1 : 0;
    } else if (cJSON_IsNumber(item)) {
        *out = (item->valueint != 0) ? 1 : 0;
    }
}

static esp_err_t wifi_config_get_handler(httpd_req_t *req)
{
    const wifi_manager_config_t *cfg = wifi_manager_get_config();
    cJSON *j = cJSON_CreateObject();

    cJSON_AddBoolToObject(j, "enabled", cfg->enabled != 0);
    cJSON_AddBoolToObject(j, "dhcp", cfg->dhcp != 0);
    json_add_string(j, "ssid", cfg->ssid);
    json_add_string(j, "password", "");
    cJSON_AddBoolToObject(j, "password_set", cfg->password[0] != 0);
    json_add_string(j, "ip", cfg->ip);
    json_add_string(j, "mask", cfg->mask);
    json_add_string(j, "gw", cfg->gw);
    json_add_string(j, "dns1", cfg->dns1);
    json_add_string(j, "dns2", cfg->dns2);

    char *out = cJSON_PrintUnformatted(j);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out ? out : "{}");

    if (out) free(out);
    cJSON_Delete(j);
    return ESP_OK;
}

static esp_err_t wifi_config_post_handler(httpd_req_t *req)
{
    int len = req->content_len;
    if (len <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "empty body");
        return ESP_OK;
    }

    char *buf = malloc(len + 1);
    if (!buf) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "no mem");
        return ESP_OK;
    }

    int off = 0;
    while (off < len) {
        int r = httpd_req_recv(req, buf + off, len - off);
        if (r <= 0) {
            free(buf);
            httpd_resp_set_status(req, "500 Internal Server Error");
            httpd_resp_sendstr(req, "recv error");
            return ESP_OK;
        }
        off += r;
    }
    buf[off] = 0;

    cJSON *root = cJSON_Parse(buf);
    free(buf);

    if (!root) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "invalid json");
        return ESP_OK;
    }

    wifi_manager_config_t next = *wifi_manager_get_config();
    json_copy_u8(root, "enabled", &next.enabled);
    json_copy_u8(root, "dhcp", &next.dhcp);
    json_copy_string(root, "ssid", next.ssid, sizeof(next.ssid));
    json_copy_string(root, "password", next.password, sizeof(next.password));
    json_copy_string(root, "ip", next.ip, sizeof(next.ip));
    json_copy_string(root, "mask", next.mask, sizeof(next.mask));
    json_copy_string(root, "gw", next.gw, sizeof(next.gw));
    json_copy_string(root, "dns1", next.dns1, sizeof(next.dns1));
    json_copy_string(root, "dns2", next.dns2, sizeof(next.dns2));

    cJSON_Delete(root);

    esp_err_t er = wifi_manager_set_config(&next, true);
    if (er != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "save failed");
        return ESP_OK;
    }

    if (!next.enabled || next.ssid[0] == 0) {
        wifi_manager_stop();
    } else if (!(ethernet_is_link_up() || ethernet_has_ip())) {
        wifi_manager_start();
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t uplink_status_handler(httpd_req_t *req)
{
    cJSON *j = cJSON_CreateObject();

    bool eth_link = ethernet_is_link_up();
    bool eth_ip   = ethernet_has_ip();
    bool wifi_started = wifi_manager_is_started();
    bool wifi_conn    = wifi_manager_is_connected();
    bool wifi_ip      = wifi_manager_has_ip();

    cJSON_AddBoolToObject(j, "eth_link", eth_link);
    cJSON_AddBoolToObject(j, "eth_ip", eth_ip);
    cJSON_AddBoolToObject(j, "wifi_started", wifi_started);
    cJSON_AddBoolToObject(j, "wifi_connected", wifi_conn);
    cJSON_AddBoolToObject(j, "wifi_ip", wifi_ip);
    json_add_string(j, "wifi_addr", wifi_manager_get_ip_str());

    if (eth_link || eth_ip) {
        cJSON_AddStringToObject(j, "active_uplink", "ethernet");
    } else if (wifi_started || wifi_conn || wifi_ip) {
        cJSON_AddStringToObject(j, "active_uplink", "wifi");
    } else {
        cJSON_AddStringToObject(j, "active_uplink", "none");
    }

    char *out = cJSON_PrintUnformatted(j);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out ? out : "{}");

    if (out) free(out);
    cJSON_Delete(j);
    return ESP_OK;
}

static esp_err_t wifi_page_handler(httpd_req_t *req)
{
    static const char *HTML =
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Wi-Fi config</title>"
        "<style>body{font-family:sans-serif;max-width:760px;margin:24px auto;padding:0 12px}"
        "label{display:block;margin:10px 0 4px}input[type=text],input[type=password]{width:100%;padding:8px}"
        ".row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.muted{color:#666;font-size:13px}"
        "button{margin-top:16px;padding:10px 16px}</style></head><body>"
        "<h1>Wi-Fi beállítás</h1>"
        "<p class='muted'>Ethernet link esetén a Wi-Fi automatikusan leáll, Ethernet hiányában fallbackként indul.</p>"
        "<div id='status' class='muted'>Betöltés...</div>"
        "<label><input id='enabled' type='checkbox'> Wi-Fi engedélyezve</label>"
        "<label><input id='dhcp' type='checkbox'> DHCP</label>"
        "<label>SSID</label><input id='ssid' type='text'>"
        "<label>Jelszó</label><input id='password' type='password' placeholder='Üresen hagyva marad a mentett'>"
        "<div class='row'>"
        "<div><label>IP</label><input id='ip' type='text'></div>"
        "<div><label>Maszk</label><input id='mask' type='text'></div>"
        "<div><label>Gateway</label><input id='gw' type='text'></div>"
        "<div><label>DNS1</label><input id='dns1' type='text'></div>"
        "<div><label>DNS2</label><input id='dns2' type='text'></div>"
        "</div>"
        "<button onclick='saveCfg()'>Mentés</button>"
        "<script>"
        "async function refresh(){"
        " const s=await fetch('/api/uplink_status').then(r=>r.json());"
        " const c=await fetch('/api/wifi_config').then(r=>r.json());"
        " document.getElementById('status').textContent='Aktív uplink: '+s.active_uplink+' | Wi-Fi IP: '+(s.wifi_addr||'-');"
        " enabled.checked=!!c.enabled; dhcp.checked=!!c.dhcp; ssid.value=c.ssid||'';"
        " ip.value=c.ip||''; mask.value=c.mask||''; gw.value=c.gw||''; dns1.value=c.dns1||''; dns2.value=c.dns2||'';"
        "}"
        "async function saveCfg(){"
        " const body={enabled:enabled.checked,dhcp:dhcp.checked,ssid:ssid.value,password:password.value,ip:ip.value,mask:mask.value,gw:gw.value,dns1:dns1.value,dns2:dns2.value};"
        " const r=await fetch('/api/wifi_config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});"
        " if(!r.ok){alert('Mentés sikertelen');return;} password.value=''; await refresh(); alert('Mentve');"
        "}"
        "refresh(); setInterval(refresh,3000);"
        "</script></body></html>";

    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, HTML, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* ====== HTTP route regisztrálás ====== */

static const httpd_uri_t uri_dwm_get = {
    .uri      = "/api/dwm_get",
    .method   = HTTP_GET,
    .handler  = dwm_get_handler,
    .user_ctx = NULL
};

static const httpd_uri_t uri_dwm_set = {
    .uri      = "/api/dwm_set",
    .method   = HTTP_POST,
    .handler  = handle_dwm_set,
    .user_ctx = NULL
};

static const httpd_uri_t uri_dwm_last = {
    .uri      = "/api/dwm_last",
    .method   = HTTP_GET,
    .handler  = dwm_last_handler,
    .user_ctx = NULL
};

static const httpd_uri_t uri_wifi_cfg_get = {
    .uri      = "/api/wifi_config",
    .method   = HTTP_GET,
    .handler  = wifi_config_get_handler,
    .user_ctx = NULL
};

static const httpd_uri_t uri_wifi_cfg_post = {
    .uri      = "/api/wifi_config",
    .method   = HTTP_POST,
    .handler  = wifi_config_post_handler,
    .user_ctx = NULL
};

static const httpd_uri_t uri_uplink_status = {
    .uri      = "/api/uplink_status",
    .method   = HTTP_GET,
    .handler  = uplink_status_handler,
    .user_ctx = NULL
};

static const httpd_uri_t uri_wifi_page = {
    .uri      = "/wifi.html",
    .method   = HTTP_GET,
    .handler  = wifi_page_handler,
    .user_ctx = NULL
};

void http_register_routes(httpd_handle_t h)
{
    httpd_register_uri_handler(h, &uri_dwm_get);
    httpd_register_uri_handler(h, &uri_dwm_set);
    httpd_register_uri_handler(h, &uri_dwm_last);
    httpd_register_uri_handler(h, &uri_wifi_cfg_get);
    httpd_register_uri_handler(h, &uri_wifi_cfg_post);
    httpd_register_uri_handler(h, &uri_uplink_status);
    httpd_register_uri_handler(h, &uri_wifi_page);
}

void ble_http_bridge_init(void)
{
    if(!s_q){
        s_q = xQueueCreate(8, sizeof(frame_t*));
    }
    if(!s_sem_ack) s_sem_ack = xSemaphoreCreateBinary();
    if(!s_sem_tlv) s_sem_tlv = xSemaphoreCreateBinary();
    if(!s_ble_lock) s_ble_lock = xSemaphoreCreateMutex();
    if(!s_worker){
        xTaskCreatePinnedToCore(tlv_worker_task, "tlv_worker", 3072, NULL, 5, &s_worker, tskNO_AFFINITY);
    }
    static bool cb_reg = false;
    if(!cb_reg){
        ble_register_notify_cb(on_ble_notify);
        cb_reg = true;
    }
}

uint8_t hb_get_status(void)
{
    return s_cfg.have[H_STATUS] ? s_cfg.status : 0;
}

uint32_t hb_get_uptime_ms(void)
{
    return s_cfg.have[H_UPTIME_MS] ? s_cfg.uptime_ms : 0;
}

uint32_t hb_get_sync_ms(void)
{
    return s_cfg.have[H_SYNC_MS] ? s_cfg.sync_ms : 0;
}

bool hb_has_status(void)
{
    return s_cfg.have[H_STATUS];
}
