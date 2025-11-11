// components/webserver/http_server.c
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "esp_http_server.h"
#include "esp_log.h"

#include "cJSON.h"
#include "ble.h"  // ble_register_notify_cb(), ble_send_get()

/* ====== Általános ====== */
static const char* TAG = "HTTP_BRIDGE";

/* Egy kérés sorosítása mindenki számára */
static SemaphoreHandle_t s_ble_lock;          // globális mutex
static SemaphoreHandle_t s_sem_ack;           // ACK jelzés
static SemaphoreHandle_t s_sem_tlv;           // első TLV megérkezett

/* BLE → feldolgozó sor (callbackben csak ide írunk) */
typedef struct {
    uint16_t len;
    bool     from_cfg;
    uint8_t  data[];          // rugalmas tömbvég
} frame_t;

static QueueHandle_t   s_q;                   // bejövő keretek
static TaskHandle_t    s_worker;              // feldolgozó task

/* ====== Az aktuális, összeálló konfiguráció ====== */
static struct {
    uint16_t network_id, zone_id, hb_ms, phy_sfdto;
    uint32_t anchor_id;
    int32_t  tx_ant_dly, rx_ant_dly, bias_ticks;
    uint8_t  log_level, phy_ch;
    bool     have[10];
} s_cfg;

/* ====== Segédek ====== */
static inline uint16_t rd16be(const uint8_t* p){ return ((uint16_t)p[0] << 8) | p[1]; }
static inline uint32_t rd32be(const uint8_t* p){ return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

static void reset_cfg(void){
    memset(&s_cfg, 0, sizeof(s_cfg));
}

/* TLV blokk feldolgozása. Visszaadja, hogy legalább egy mező frissült-e. */
static bool parse_tlvs_and_update(const uint8_t* p, uint16_t n){
    if(!p || n < 2) return false;
    bool changed = false;

    /* első ver blokk átugrása (T=0x00) ha van */
    if(n >= 2 && p[0] == 0x00){
        uint8_t l = p[1];
        if(n >= 2 + l){ p += 2 + l; n -= 2 + l; }
    }

    while(n >= 2){
        uint8_t t = p[0], l = p[1];
        p += 2; n -= 2;
        if(n < l) break;

        switch(t){
            case 0x10: if(l==2){ s_cfg.network_id = rd16be(p); s_cfg.have[0]=true; changed=true; } break;
            case 0x11: if(l==2){ s_cfg.zone_id    = rd16be(p); s_cfg.have[1]=true; changed=true; } break;
            case 0x12: if(l==4){ s_cfg.anchor_id  = rd32be(p); s_cfg.have[2]=true; changed=true; } break;
            case 0x20: if(l==2){ s_cfg.hb_ms      = rd16be(p); s_cfg.have[3]=true; changed=true; } break;
            case 0x1F: if(l==1){ s_cfg.log_level  = p[0];      s_cfg.have[4]=true; changed=true; } break;
            case 0x13: if(l==4){ s_cfg.tx_ant_dly = (int32_t)rd32be(p); s_cfg.have[5]=true; changed=true; } break;
            case 0x14: if(l==4){ s_cfg.rx_ant_dly = (int32_t)rd32be(p); s_cfg.have[6]=true; changed=true; } break;
            case 0x16: if(l==4){ s_cfg.bias_ticks = (int32_t)rd32be(p); s_cfg.have[7]=true; changed=true; } break;
            case 0x40: if(l==1){ s_cfg.phy_ch     = p[0];      s_cfg.have[8]=true; changed=true; } break;
            case 0x49: if(l==2){ s_cfg.phy_sfdto  = rd16be(p); s_cfg.have[9]=true; changed=true; } break;
            default: break;
        }
        p += l; n -= l;
    }
    return changed;
}

/* ====== BLE notify callback → csak sorba tesz ====== */
static void on_ble_notify(const uint8_t* p, uint16_t n, bool from_cfg)
{
    if(!p || n==0) return;

    /* ACK: [1, 0x81, req_hi, req_lo, status, applied] */
    if(n==6 && p[0]==1 && p[1]==0x81){
        /* csak jelez, semmi extra munka itt */
        xSemaphoreGive(s_sem_ack);
        return;
    }

    /* egyéb: be a sorba, ne blokkoljon */
    frame_t* f = (frame_t*)pvPortMalloc(sizeof(frame_t) + n);
    if(!f) return;
    f->len = n;
    f->from_cfg = from_cfg;
    memcpy(f->data, p, n);

    (void)xQueueSend(s_q, &f, 0);   // ha tele, eldobjuk
}

/* ====== Feldolgozó task ====== */
static void tlv_worker_task(void* arg)
{
    frame_t* f = NULL;
    for(;;){
        if(xQueueReceive(s_q, &f, portMAX_DELAY) != pdTRUE) continue;
        if(f){
            if(f->from_cfg){
                bool changed = parse_tlvs_and_update(f->data, f->len);
                if(changed){
                    /* első TLV megjött → ébresszük a várakozót */
                    xSemaphoreGive(s_sem_tlv);
                }
            }
            vPortFree(f);
        }
    }
}

/* Sor kiürítése egy új kérés előtt */
static void drain_queue(void){
    frame_t* f=NULL;
    while(xQueueReceive(s_q, &f, 0)==pdTRUE){
        if(f) vPortFree(f);
    }
}

/* ====== HTTP handler: /api/dwm_get ====== */
static esp_err_t dwm_get_handler(httpd_req_t* req)
{
    if(!s_ble_lock) s_ble_lock = xSemaphoreCreateMutex();
    xSemaphoreTake(s_ble_lock, portMAX_DELAY);

    if(!s_sem_ack) s_sem_ack = xSemaphoreCreateBinary();
    if(!s_sem_tlv) s_sem_tlv = xSemaphoreCreateBinary();

    /* init */
    reset_cfg();
    drain_queue();
    xSemaphoreTake(s_sem_ack, 0);
    xSemaphoreTake(s_sem_tlv, 0);

    static uint16_t s_last_req = 0;
    s_last_req++;
    ble_send_get(s_last_req);

    /* ACK várakozás */
    if(xSemaphoreTake(s_sem_ack, pdMS_TO_TICKS(2000)) != pdTRUE){
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "ACK timeout");
        xSemaphoreGive(s_ble_lock);
        return ESP_FAIL;
    }

    /* első TLV blokk(ig) várakozás, majd kis puffer, hogy beérjen minden */
    (void)xSemaphoreTake(s_sem_tlv, pdMS_TO_TICKS(2000));
    vTaskDelay(pdMS_TO_TICKS(200));

    /* JSON építés */
    cJSON* j = cJSON_CreateObject();
    if(s_cfg.have[0]) cJSON_AddNumberToObject(j,"NETWORK_ID", s_cfg.network_id);
    if(s_cfg.have[1]) cJSON_AddNumberToObject(j,"ZONE_ID",    s_cfg.zone_id);
    if(s_cfg.have[2]){
        char hex[11];
        snprintf(hex, sizeof hex, "0x%08" PRIX32, (uint32_t)s_cfg.anchor_id);
        cJSON_AddStringToObject(j, "ANCHOR_ID", hex);
    }
    if(s_cfg.have[3]) cJSON_AddNumberToObject(j,"HB_MS",      s_cfg.hb_ms);
    if(s_cfg.have[4]) cJSON_AddNumberToObject(j,"LOG_LEVEL",  s_cfg.log_level);
    if(s_cfg.have[5]) cJSON_AddNumberToObject(j,"TX_ANT_DLY", s_cfg.tx_ant_dly);
    if(s_cfg.have[6]) cJSON_AddNumberToObject(j,"RX_ANT_DLY", s_cfg.rx_ant_dly);
    if(s_cfg.have[7]) cJSON_AddNumberToObject(j,"BIAS_TICKS", s_cfg.bias_ticks);
    if(s_cfg.have[8]) cJSON_AddNumberToObject(j,"PHY_CH",     s_cfg.phy_ch);
    if(s_cfg.have[9]) cJSON_AddNumberToObject(j,"PHY_SFDTO",  s_cfg.phy_sfdto);

    char* out=cJSON_PrintUnformatted(j);
    httpd_resp_set_type(req,"application/json");
    httpd_resp_sendstr(req, out ? out : "{}");
    if(out) free(out);
    cJSON_Delete(j);

    xSemaphoreGive(s_ble_lock);
    return ESP_OK;
}

/* ====== HTTP route regisztrálás ====== */
void http_register_routes(httpd_handle_t h)
{
    httpd_uri_t u = {
        .uri = "/api/dwm_get",
        .method = HTTP_GET,
        .handler = dwm_get_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(h, &u);
}

/* ====== Init: sor, szemaforok, callback, worker ====== */
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
    /* csak egyszer regisztráljuk */
    static bool cb_reg = false;
    if(!cb_reg){
        ble_register_notify_cb(on_ble_notify);
        cb_reg = true;
    }
}
