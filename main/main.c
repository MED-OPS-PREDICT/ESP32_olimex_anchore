#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "ethernet.h"
#include "esp_log.h"
#include "globals.h"
#include "ble.h"
#include "pretty_print.h"
// #include "webserver.h"
#include "esp_spiffs.h"
#include "webserver.hpp"
#include "uwb_cfg_cli.h"
#include "ble_logger.h"
#include "ethernet_sender/ble_logger.h"
#include "aes_sender.h"

static const char *TAG = "main";

static void fs_mount(void){
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 8,
        .format_if_mount_failed = true
    };
    esp_err_t err = esp_vfs_spiffs_register(&conf);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "SPIFFS mount failed: %s", esp_err_to_name(err));
        return; // ne ESP_ERROR_CHECK, különben abortál
    }
}


/* ===== Kisegítő BE olvasók ===== */
static inline uint16_t rd16be(const uint8_t* v){ return ((uint16_t)v[0]<<8) | v[1]; }
static inline uint32_t rd32be(const uint8_t* v){ return ((uint32_t)v[0]<<24)|((uint32_t)v[1]<<16)|((uint32_t)v[2]<<8)|v[3]; }

/* ===== BLE NOTIFY parser ===== */
static void __attribute__((unused)) parse_cfg_notify(const uint8_t* p, uint16_t n){
    const char* TAG="CFG";
    if (n==6 && p[0]==1 && p[1]==0x81){
        uint16_t req = rd16be(&p[2]);
        uint8_t status = p[4], applied = p[5];
        (void)req; (void)status; (void)applied;   // elnyomjuk a warningokat
        return;
    }
    if (n==17 && p[0]==1 && p[1]==0x90){
        uint8_t  st    = p[2];
        uint16_t sync  = rd16be(&p[3]);
        uint32_t up    = rd32be(&p[5]);
        uint16_t netid = rd16be(&p[9]);
        uint16_t zone  = rd16be(&p[11]);
        uint32_t anc   = rd32be(&p[13]);
        (void)st; (void)sync; (void)up; (void)netid; (void)zone; (void)anc;
        return;
    }
    // TLV stream: [t,l,val...] egymás után (HB vagy GET snapshot)
    const uint8_t* q=p; uint16_t r=n;
    while (r>=2){
        uint8_t t=q[0], l=q[1]; q+=2; r-=2;
        if (r<l){ ESP_LOGW(TAG,"TRUNC tlv t=0x%02X need=%u have=%u",t,(unsigned)l,(unsigned)r); break; }
        switch(t){
            case 0x00: if(l==1) ESP_LOGI(TAG,"VER=%u", (unsigned)q[0]); break;                 // T_VER
            case 0x01: if(l==1) ESP_LOGI(TAG,"STATUS=0x%02X", (unsigned)q[0]); break;         // T_STATUS
            case 0x02: if(l==4) ESP_LOGI(TAG,"UPTIME_MS=%u", (unsigned)rd32be(q)); break;     // T_UPTIME_MS
            case 0x03: if(l==2) ESP_LOGI(TAG,"SYNC_MS=%u", (unsigned)rd16be(q)); break;       // T_SYNC_MS
            case 0x10: if(l==2) ESP_LOGI(TAG,"NETWORK_ID=%u", (unsigned)rd16be(q)); break;
            case 0x11: if(l==2) ESP_LOGI(TAG,"ZONE_ID=0x%04X", (unsigned)rd16be(q)); break;
            case 0x12: if(l==4) ESP_LOGI(TAG,"ANCHOR_ID=0x%08X", (unsigned)rd32be(q)); break;
            case 0x13: if(l==4) ESP_LOGI(TAG,"TX_ANT_DLY=%" PRId32, (int32_t)rd32be(q)); break;
            case 0x14: if(l==4) ESP_LOGI(TAG,"RX_ANT_DLY=%" PRId32, (int32_t)rd32be(q)); break;
            case 0x16: if(l==4) ESP_LOGI(TAG,"BIAS_TICKS=%" PRId32, (int32_t)rd32be(q)); break;
            case 0x1F: if(l==1) ESP_LOGI(TAG,"LOG_LEVEL=%u", (unsigned)q[0]); break;
            case 0x20: if(l==2) ESP_LOGI(TAG,"HB_MS=%u", (unsigned)rd16be(q)); break;
            case 0x30: if(l==2) ESP_LOGI(TAG,"PPM_MAX=%u", (unsigned)rd16be(q)); break;
            case 0x31: if(l==2) ESP_LOGI(TAG,"JUMP_PPM=%u", (unsigned)rd16be(q)); break;
            case 0x32: if(l==2) ESP_LOGI(TAG,"AB_GAP_MS=%u", (unsigned)rd16be(q)); break;
            case 0x33: if(l==1) ESP_LOGI(TAG,"MS_EWMA_DEN=%u", (unsigned)q[0]); break;
            case 0x34: if(l==1) ESP_LOGI(TAG,"TK_EWMA_DEN=%u", (unsigned)q[0]); break;
            case 0x35: if(l==2) ESP_LOGI(TAG,"TK_MIN_MS=%u", (unsigned)rd16be(q)); break;
            case 0x36: if(l==2) ESP_LOGI(TAG,"TK_MAX_MS=%u", (unsigned)rd16be(q)); break;
            case 0x37: if(l==2) ESP_LOGI(TAG,"DTTX_MIN_MS=%u", (unsigned)rd16be(q)); break;
            case 0x38: if(l==2) ESP_LOGI(TAG,"DTTX_MAX_MS=%u", (unsigned)rd16be(q)); break;
            case 0x39: if(l==1) ESP_LOGI(TAG,"LOCK_NEED=%u", (unsigned)q[0]); break;
            default:   ESP_LOGI(TAG,"TLV t=0x%02X l=%u", t, (unsigned)l); break;
        }
        q+=l; r-=l;
    }
}

static void on_ble_notify(const uint8_t* data, uint16_t len, bool from_cfg) {
    //ESP_LOGI("BLE", "[%s] len=%u", from_cfg ? "CFG" : "DATA", (unsigned)len);
    if (from_cfg)
        pp_log_cfg(data, len, NULL, rd16be, rd32be);
    else
        pp_log_data(data, len);
}

/* ===== SET példa ===== */
static esp_err_t send_cfg_example(void) {
    /* NETWORK_ID=2 (T=0x10, l=2), HB_MS=5000 (T=0x20, l=2) */
    uint8_t tlv[2+2 + 2+2];
    uint8_t *w = tlv;
    *w++ = 0x10; *w++ = 2; *w++ = 0x00; *w++ = 0x02;
    *w++ = 0x20; *w++ = 2; *w++ = 0x13; *w++ = 0x88; // 5000
    return ble_send_set(2, tlv, sizeof(tlv));
}

static void nvs_init_or_erase(void){
    esp_err_t r=nvs_flash_init();
    if(r==ESP_ERR_NVS_NO_FREE_PAGES || r==ESP_ERR_NVS_NEW_VERSION_FOUND){ nvs_flash_erase(); nvs_flash_init(); }
}

void app_main(void)
{
    globals_init();
    nvs_init_or_erase();
    esp_event_loop_create_default();
    esp_netif_init();

    ethernet_ctx_t eth = {0};
    ethernet_init(&eth);

    vTaskDelay(pdMS_TO_TICKS(500));
    fs_mount();
    webserver_start();

    /* BLE: opcionális name filter, pl. "UWB_ANCHOR_01" */
    ble_start("UWB_ANCHOR_01", on_ble_notify);
    uwb_cfg_cli_init();
    ble_register_notify_cb(uwb_notify_cb);

    // példa GET kérés 600ms után:
    vTaskDelay(pdMS_TO_TICKS(600));
    ble_send_get(1);

    // példa SET 1s után
    vTaskDelay(pdMS_TO_TICKS(400));
    send_cfg_example();
}
