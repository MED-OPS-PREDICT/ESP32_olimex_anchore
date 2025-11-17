// components/ble/ble.c — ESP-IDF v5.4, Bluedroid GATTC kliens UWB CFG/DATA-hoz
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_gattc_api.h"
#include "esp_gatt_common_api.h"

#include "ble.h"   // ble_start / ble_send_get / ble_send_set / ble_register_notify_cb

/* ====== Állapot ====== */
static const char* TAG = "BLE_CLI";
static uint16_t g_mtu = 23;

static esp_gatt_if_t g_gattc_if = 0xFE;
static uint16_t      g_conn_id  = 0xFFFF;
static esp_bd_addr_t g_peer_bda = {0};
static esp_ble_addr_type_t g_peer_addr_type = BLE_ADDR_TYPE_PUBLIC;
static bool g_connected = false;
volatile int ble_up = 0;

static uint16_t g_start_handle=0, g_end_handle=0;
static uint16_t g_data_h=0, g_cfg_h=0;
static uint16_t g_data_ccc_h=0, g_cfg_ccc_h=0;

static ble_notify_cb_t g_cb = NULL;
static char g_name_filter[32] = {0};
static bool g_connecting = false;
static bool s_verbose_tlv = false;   // állítsd true-ra, ha részletes TLV dump kell
static bool s_log_progress  = false;

#define LOGP_I(...)  do{ if(s_log_progress) ESP_LOGI(TAG, __VA_ARGS__); }while(0)
#define LOGP_W(...)  do{ if(s_log_progress) ESP_LOGW(TAG, __VA_ARGS__); }while(0)

/* ====== Protokoll opkódok ====== */
#define OP_GET    0x02
#define OP_START  0x82
#define OP_LINE   0x83
#define OP_ACK    0x84
#define OP_DONE   0x85
#define OP_ERR    0xE0

/* ===== TLV ID-k (a DWM oldallal egyezőek) ===== */
#define T_VER             0x00
#define T_STATUS          0x01
#define T_UPTIME_MS       0x02
#define T_SYNC_MS         0x03
#define T_DIAG            0x04

#define T_NETWORK_ID      0x10  /* u16 BE */
#define T_ZONE_ID         0x11  /* u16 BE (2 ASCII) */
#define T_ANCHOR_ID       0x12  /* u32 BE */
#define T_TX_ANT_DLY      0x13  /* i32 BE */
#define T_RX_ANT_DLY      0x14  /* i32 BE */
#define T_BIAS_TICKS      0x16  /* i32 BE */
#define T_LOG_LEVEL       0x1F  /* u8  */
#define T_HB_MS           0x20  /* u16 BE */

#define T_SYN_PPM_MAX     0x30  /* u16 BE */
#define T_SYN_JUMP_PPM    0x31  /* u16 BE */
#define T_SYN_AB_GAP_MS   0x32  /* u16 BE */
#define T_SYN_MS_EWMA_DEN 0x33  /* u8  */
#define T_SYN_TK_EWMA_DEN 0x34  /* u8  */
#define T_SYN_TK_MIN_MS   0x35  /* u16 BE */
#define T_SYN_TK_MAX_MS   0x36  /* u16 BE */
#define T_SYN_DTTX_MIN_MS 0x37  /* u16 BE */
#define T_SYN_DTTX_MAX_MS 0x38  /* u16 BE */
#define T_SYN_LOCK_NEED   0x39  /* u8  */

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

/* ====== UWB UUID-k ======
 * Service:  12345678-1234-5678-1234-1234567890AB
 * DATA:     ABCDEF01-1234-5678-1234-1234567890AB
 * CFG:      ABCDEF02-1234-5678-1234-1234567890AB
 */

/* ---- SCAN állapot ---- */
static bool s_params_set = false, s_scan_active = false;
static bool s_scan_pending = false;   /* start kérve, START_COMPLETE-re várunk */

static esp_ble_scan_params_t s_scan_params = {
    .scan_type              = BLE_SCAN_TYPE_ACTIVE,
    .own_addr_type          = BLE_ADDR_TYPE_PUBLIC,
    .scan_filter_policy     = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_interval          = 0x50,
    .scan_window            = 0x30,
    .scan_duplicate         = BLE_SCAN_DUPLICATE_DISABLE
};

/* ---- SCAN/CONNECT sorosítás + védett hívások (elődeklaráció) ---- */
static esp_err_t start_scan_safe(uint32_t dur_sec);
static esp_err_t gattc_open_safe(esp_gatt_if_t ifx, const esp_bd_addr_t addr, esp_ble_addr_type_t type);

/* ---- UUID-k ---- */
static const uint8_t UWB_SVC_UUID_128[16]  = { 0xAB,0x90,0x78,0x56,0x34,0x12,0x34,0x12,0x78,0x56,0x34,0x12,0x78,0x56,0x34,0x12 };
static const uint8_t UWB_SVC_UUID_128_BE[16]= { 0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x12,0x34,0x56,0x78,0x90,0xAB };
static const uint8_t UWB_DATA_UUID_128[16] = { 0xAB,0x90,0x78,0x56,0x34,0x12,0x34,0x12,0x78,0x56,0x34,0x12,0x01,0xEF,0xCD,0xAB };
static const uint8_t UWB_CFG_UUID_128[16]  = { 0xAB,0x90,0x78,0x56,0x34,0x12,0x34,0x12,0x78,0x56,0x34,0x12,0x02,0xEF,0xCD,0xAB };

static esp_bt_uuid_t uuid16(uint16_t u){ esp_bt_uuid_t x={.len=ESP_UUID_LEN_16,.uuid.uuid16=u}; return x; }
static esp_bt_uuid_t uuid128(const uint8_t u[16]){ esp_bt_uuid_t x={.len=ESP_UUID_LEN_128}; memcpy(x.uuid.uuid128,u,16); return x; }

/* ====== Segédek ====== */
static bool adv_name_match(const uint8_t* adv, uint8_t len, const char* filter){
    if(!filter || !filter[0]) return true;
    uint8_t nlen=0; const uint8_t* name = esp_ble_resolve_adv_data((uint8_t*)adv, ESP_BLE_AD_TYPE_NAME_CMPL, &nlen);
    if(name && nlen && nlen == strlen(filter) && memcmp(name, filter, nlen)==0) return true;
    name = esp_ble_resolve_adv_data((uint8_t*)adv, ESP_BLE_AD_TYPE_NAME_SHORT, &nlen);
    return (name && nlen && nlen == strlen(filter) && memcmp(name, filter, nlen)==0);
}

static void reset_gatt_state(void){
    g_start_handle=g_end_handle=0;
    g_data_h=g_cfg_h=0;
    g_data_ccc_h=g_cfg_ccc_h=0;
}

/* ---- TLV ID-k után, a rx_emit_summary_to_cb ELÉ ---- */
static const char* tlv_name(uint8_t t){
    switch(t){
      case T_NETWORK_ID: return "NETWORK_ID";
      case T_ZONE_ID:    return "ZONE_ID";
      case T_ANCHOR_ID:  return "ANCHOR_ID";
      case T_TX_ANT_DLY: return "TX_ANT_DLY";
      case T_RX_ANT_DLY: return "RX_ANT_DLY";
      case T_BIAS_TICKS: return "BIAS_TICKS";
      case T_LOG_LEVEL:  return "LOG_LEVEL";
      case T_HB_MS:      return "HB_MS";

      case T_SYN_PPM_MAX:     return "PPM_MAX";
      case T_SYN_JUMP_PPM:    return "JUMP_PPM";
      case T_SYN_AB_GAP_MS:   return "AB_GAP_MS";
      case T_SYN_MS_EWMA_DEN: return "MS_EWMA_DEN";
      case T_SYN_TK_EWMA_DEN: return "TK_EWMA_DEN";
      case T_SYN_TK_MIN_MS:   return "TK_MIN_MS";
      case T_SYN_TK_MAX_MS:   return "TK_MAX_MS";
      case T_SYN_DTTX_MIN_MS: return "DTTX_MIN_MS";
      case T_SYN_DTTX_MAX_MS: return "DTTX_MAX_MS";
      case T_SYN_LOCK_NEED:   return "LOCK_NEED";

      case T_PHY_CH:      return "PHY_CH";
      case T_PHY_PLEN:    return "PHY_PLEN";
      case T_PHY_PAC:     return "PHY_PAC";
      case T_PHY_TX_CODE: return "PHY_TX_CODE";
      case T_PHY_RX_CODE: return "PHY_RX_CODE";
      case T_PHY_SFD:     return "PHY_SFD";
      case T_PHY_BR:      return "PHY_BR";
      case T_PHY_PHRMODE: return "PHY_PHRMODE";
      case T_PHY_PHRRATE: return "PHY_PHRRATE";
      case T_PHY_SFDTO:   return "PHY_SFDTO";
      case T_PHY_STS_MODE:return "PHY_STS_MODE";
      case T_PHY_STS_LEN: return "PHY_STS_LEN";
      case T_PHY_PDOA:    return "PHY_PDOA";
      default:            return "UNKNOWN";
    }
}

/* ===== TLV ki/bemenet segéd ===== */
static inline uint16_t rd16be(const uint8_t* v){ return ((uint16_t)v[0]<<8) | v[1]; }
static inline uint32_t rd32be(const uint8_t* v){ return ((uint32_t)v[0]<<24)|((uint32_t)v[1]<<16)|((uint32_t)v[2]<<8)|v[3]; }

/* ====== STREAM (GET ÖSSZES) kliens oldali állapotgép ====== */

struct kv_entry { bool present; uint8_t len; uint8_t val[8]; };
struct kv_set   { struct kv_entry e[256]; };

static const uint8_t s_expected_tags[] = {
    T_NETWORK_ID, T_ZONE_ID, T_ANCHOR_ID, T_TX_ANT_DLY, T_RX_ANT_DLY, T_BIAS_TICKS, T_LOG_LEVEL, T_HB_MS,
    T_SYN_PPM_MAX, T_SYN_JUMP_PPM, T_SYN_AB_GAP_MS, T_SYN_MS_EWMA_DEN, T_SYN_TK_EWMA_DEN,
    T_SYN_TK_MIN_MS, T_SYN_TK_MAX_MS, T_SYN_DTTX_MIN_MS, T_SYN_DTTX_MAX_MS, T_SYN_LOCK_NEED,
    T_PHY_CH, T_PHY_PLEN, T_PHY_PAC, T_PHY_TX_CODE, T_PHY_RX_CODE, T_PHY_SFD, T_PHY_BR,
    T_PHY_PHRMODE, T_PHY_PHRRATE, T_PHY_SFDTO, T_PHY_STS_MODE, T_PHY_STS_LEN, T_PHY_PDOA
};

static struct {
    bool   active;
    uint16_t req_id;
    uint16_t total;
    uint8_t  *bitmap;       /* bitset az érkezett sorokról */
    uint16_t bitmap_len;
    uint16_t got;           /* hány sor jött meg */
    uint8_t  section;       /* 0: ismeretlen, 1: CURRENT (T_VER=1), 2: DEFAULTS (T_VER=2) */
    struct kv_set cur, def; /* két „tükör” */
} s_rx = {0};

static void __attribute__((unused)) log_tlv_compact(uint8_t section, uint8_t t, const uint8_t* v, uint8_t l){
    if (!s_verbose_tlv) return;
    const char* sec = (section==1) ? "CUR" : (section==2) ? "DEF" : "?";
    const char* nm  = tlv_name(t);
    if (l==1)      ESP_LOGI(TAG, "%s.%s=%u", sec, nm, (unsigned)v[0]);
    else if (l==2) ESP_LOGI(TAG, "%s.%s=%u", sec, nm, (unsigned)rd16be(v));
    else if (l==4) ESP_LOGI(TAG, "%s.%s=%u", sec, nm, (unsigned)rd32be(v));
    else           ESP_LOGI(TAG, "%s.%s(len=%u)", sec, nm, (unsigned)l);
}

static inline void rx_reset(void){
    if (s_rx.bitmap) { free(s_rx.bitmap); }
    memset(&s_rx, 0, sizeof(s_rx));
}
static inline void bitset_set(uint16_t idx){
    if (!s_rx.bitmap) return;
    uint16_t byte = idx >> 3, bit = idx & 7;
    if (byte < s_rx.bitmap_len) s_rx.bitmap[byte] |= (1u << bit);
}
static inline bool bitset_get(uint16_t idx){
    if (!s_rx.bitmap) return false;
    uint16_t byte = idx >> 3, bit = idx & 7;
    return (byte < s_rx.bitmap_len) ? (s_rx.bitmap[byte] & (1u<<bit)) != 0 : false;
}
static inline esp_err_t send_ack(uint16_t req_id, uint16_t line_no, uint8_t status){
    if (!g_connected || !g_cfg_h) return ESP_ERR_INVALID_STATE;
    uint8_t ack[1+1+2+2+1] = {1, OP_ACK, 0,0, 0,0, 0};
    ack[6] = status;
    ack[2] = (uint8_t)(req_id >> 8); ack[3] = (uint8_t)req_id;
    ack[4] = (uint8_t)(line_no>> 8); ack[5] = (uint8_t)line_no;
    return esp_ble_gattc_write_char(g_gattc_if, g_conn_id, g_cfg_h,
                                    sizeof(ack), ack,
                                    ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
}
static inline void kv_store(struct kv_set* S, uint8_t t, const uint8_t* v, uint8_t l){
    struct kv_entry* e = &S->e[t];
    e->present = true;
    e->len     = l > sizeof(e->val) ? sizeof(e->val) : l;
    memcpy(e->val, v, e->len);
}

/* helper: 8/16/32 bites értékek egysoros kiírása – fájl-szint */
static void print_kv(const char* key, const struct kv_entry* e){
    if (!e || !e->present) { ESP_LOGI(TAG, "%s=?", key); return; }
    if (e->len == 1) {
        ESP_LOGI(TAG, "%s=%u", key, (unsigned)e->val[0]);
    } else if (e->len == 2) {
        ESP_LOGI(TAG, "%s=%u", key, (unsigned)rd16be(e->val));
    } else if (e->len == 4) {
        ESP_LOGI(TAG, "%s=%u", key, (unsigned)rd32be(e->val));
    } else {
        ESP_LOGI(TAG, "%s=LEN%u", key, (unsigned)e->len);
    }
}

/* --- összefoglaló a felsőbb rétegnek --- */
static void rx_emit_summary_to_cb(void){
    // csak a végén, rendezett "name=value" sorok
    for (size_t i = 0; i < sizeof(s_expected_tags); ++i) {
        uint8_t t = s_expected_tags[i];
        const char* name = tlv_name(t);

        // CURRENT
        print_kv(name, &s_rx.cur.e[t]);

        // DEFAULTS külön sorban, _DEF suffix
        char def_name[48];
        int n = snprintf(def_name, sizeof(def_name), "%s_DEF", name);
        if (n > 0 && (size_t)n < sizeof(def_name)) {
            print_kv(def_name, &s_rx.def.e[t]);
        }
    }

    // jelzés a felső rétegnek
    if (g_cb) {
        const char done[] = "# CFG_DONE\n";
        g_cb((const uint8_t*)done, (uint16_t)strlen(done), true);
    }
}


static void handle_cfg_notify(const uint8_t* p, uint16_t n)
{
    if (n < 2) return;
    uint8_t ver = p[0], op = p[1];

    if (ver != 1) {
        ESP_LOGW(TAG, "CFG ver=%u nem támogatott", ver);
        return;
    }

    if (op == OP_START){
        if (n < 1+1+2+2) { ESP_LOGW(TAG, "START túl rövid"); return; }
        uint16_t req_id = ((uint16_t)p[2]<<8)|p[3];
        uint16_t total  = ((uint16_t)p[4]<<8)|p[5];

        rx_reset();
        s_rx.active  = true;
        s_rx.req_id  = req_id;
        s_rx.total   = total;
        s_rx.section = 0;
        s_rx.bitmap_len = (uint16_t)((total + 7u) >> 3);
        s_rx.bitmap = (uint8_t*)calloc(s_rx.bitmap_len ? s_rx.bitmap_len : 1, 1);
        // ESP_LOGI(TAG, "CFG START req=%u total=%u", req_id, total);
        LOGP_I("CFG START req=%u total=%u", req_id, total);
        return;
    }

    if (op == OP_LINE){
        if (!s_rx.active){ ESP_LOGW(TAG, "LINE session nélkül"); return; }
        if (n < 1+1+2+2){ ESP_LOGW(TAG, "LINE túl rövid"); return; }

        uint16_t req_id = ((uint16_t)p[2]<<8)|p[3];
        uint16_t line_no= ((uint16_t)p[4]<<8)|p[5];

        if (req_id != s_rx.req_id){
            ESP_LOGW(TAG, "LINE idegen req=%u (várt=%u)", req_id, s_rx.req_id);
            (void)send_ack(req_id, line_no, 1);
            return;
        }

        const uint8_t* d = p + 6;
        const uint8_t* e = p + n;
        uint8_t status = 0;

        while (d + 2 <= e){
            uint8_t t = d[0], l = d[1];
            d += 2;
            if (d + l > e) { status = 2; break; }
            const uint8_t* v = d;

            if (t == T_VER && l==1){
                uint8_t x = v[0];
                s_rx.section = (x==1) ? 1 : (x==2) ? 2 : 0;
            } else {
                if (s_rx.section == 1) kv_store(&s_rx.cur, t, v, l);
                else if (s_rx.section == 2) kv_store(&s_rx.def, t, v, l);
                else kv_store(&s_rx.cur, t, v, l);
            }
            d += l;
        }

        if (!bitset_get(line_no)){ bitset_set(line_no); s_rx.got++; }

        esp_err_t er = send_ack(req_id, line_no, status);
        /* emberi, egy soros, kódnévvel */
        const char* st = (status==0) ? "OK" : (status==1) ? "TRUNC" : "OVERFLOW";
        /*ESP_LOGI(TAG, "CFG ▷ LINE %u/%u %s, ack=%s(0x%x)",
                 (unsigned)(line_no+1), (unsigned)s_rx.total, st,
                 esp_err_to_name(er), er);*/
        LOGP_I("CFG LINE %u/%u %s, ack=%s(0x%x)",
               (unsigned)(line_no+1), (unsigned)s_rx.total, st,
               esp_err_to_name(er), er);
        return;
    }

    if (op == OP_DONE){
        if (!s_rx.active){ ESP_LOGW(TAG, "DONE session nélkül"); return; }
        uint16_t req_id = (n>=4) ? (((uint16_t)p[2]<<8)|p[3]) : 0xFFFF;
        if (req_id != s_rx.req_id){
            ESP_LOGW(TAG, "DONE idegen req=%u (várt=%u)", req_id, s_rx.req_id);
            return;
        }

        if (s_rx.got < s_rx.total){
            for (uint16_t i=0;i<s_rx.total;i++){
                if (!bitset_get(i)) ESP_LOGW(TAG, "Hianyzo sor: #%u", i);
            }
        }
        // ESP_LOGI(TAG, "CFG DONE req=%u got=%u/%u", req_id, s_rx.got, s_rx.total);
        LOGP_I("CFG DONE req=%u got=%u/%u", req_id, s_rx.got, s_rx.total);

        rx_emit_summary_to_cb();
        rx_reset();
        return;
    }

    if (op == OP_ERR){
        ESP_LOGW(TAG, "CFG ERR frame érkezett");
        return;
    }
}

/* ====== GAP ====== */
static void gap_cb(esp_gap_ble_cb_event_t e, esp_ble_gap_cb_param_t* p);

static esp_err_t start_scan_safe(uint32_t dur_sec)
{
    if (g_connecting) return ESP_ERR_INVALID_STATE;

    if (!s_params_set) {
        return esp_ble_gap_set_scan_params(&s_scan_params);
    }

    if (s_scan_pending) {
        return ESP_ERR_INVALID_STATE;
    }

    if (s_scan_active) {
        /* ha aktív, állítsd le, majd indítsd újra */
        esp_ble_gap_stop_scanning();
        /* lehet rövid delay szükséges, de ezt a platform függ */
    }

    esp_err_t er = esp_ble_gap_start_scanning(dur_sec);
    if (er == ESP_OK) {
        s_scan_pending = true;
    }
    return er;
}

static esp_err_t gattc_open_safe(esp_gatt_if_t ifx, const esp_bd_addr_t addr, esp_ble_addr_type_t type)
{
    if (s_scan_active) esp_ble_gap_stop_scanning();
    if (g_connecting)  return ESP_ERR_INVALID_STATE;
    g_connecting = true;
    esp_err_t er = esp_ble_gattc_open(ifx, (uint8_t*)addr, type, true);
    if (er != ESP_OK) g_connecting = false;
    return er;
}

/* publikus cb-regisztráció */
static ble_notify_cb_t g_cb1 = NULL;
static ble_notify_cb_t g_cb2 = NULL;

void ble_register_notify_cb(ble_notify_cb_t cb){
    // első hívás -> cb1, második -> cb2
    if (!g_cb1) {
        g_cb1 = cb;
        ESP_LOGI("BLE_CLI", "notify_cb1 set to %p", (void*)cb);
    } else {
        g_cb2 = cb;
        ESP_LOGI("BLE_CLI", "notify_cb2 set to %p", (void*)cb);
    }
}


/* ====== GATTC ====== */
static void gattc_cb(esp_gattc_cb_event_t e, esp_gatt_if_t gattc_if, esp_ble_gattc_cb_param_t* p);

/* ====== Publikus API ====== */
esp_err_t ble_start(const char* name_filter, ble_notify_cb_t cb)
{
    if (name_filter) {
        strncpy(g_name_filter, name_filter, sizeof(g_name_filter)-1);
        g_name_filter[sizeof(g_name_filter)-1]=0;
    } else {
        g_name_filter[0]=0;
    }
    g_cb = cb;

    esp_err_t er;
    if ((er = nvs_flash_init()) == ESP_ERR_NVS_NO_FREE_PAGES || er == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));

    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());

    ESP_ERROR_CHECK(esp_ble_gap_register_callback(gap_cb));
    ESP_ERROR_CHECK(esp_ble_gattc_register_callback(gattc_cb));
    ESP_ERROR_CHECK(esp_ble_gattc_app_register(0));

    return ESP_OK;
}

/* ====== GAP CB ====== */
static void gap_cb(esp_gap_ble_cb_event_t e, esp_ble_gap_cb_param_t* p)
{
    switch (e) {
    case ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT:
        s_params_set = (p->scan_param_cmpl.status == ESP_BT_STATUS_SUCCESS);
        if (s_params_set) start_scan_safe(0);
        break;

    case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT:
        s_scan_active  = (p->scan_start_cmpl.status == ESP_BT_STATUS_SUCCESS);
        s_scan_pending = false;
        ESP_LOGI(TAG, "scan start complete, status=0x%x", p->scan_start_cmpl.status);
        break;

    case ESP_GAP_BLE_SCAN_RESULT_EVT: {
        const esp_ble_gap_cb_param_t* sr = p;
        if (sr->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_RES_EVT) {
            if (!g_connecting && g_gattc_if != 0xFE && adv_name_match(sr->scan_rst.ble_adv, sr->scan_rst.adv_data_len, g_name_filter)) {
                memcpy(g_peer_bda, p->scan_rst.bda, 6);
                g_peer_addr_type = p->scan_rst.ble_addr_type;
                gattc_open_safe(g_gattc_if, g_peer_bda, g_peer_addr_type);
            }
        }
        break;
    }

    case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT:
        s_scan_active  = false;
        s_scan_pending = false;
        break;

    default: break;
    }
}

/* ====== CCC write ====== */
static void enable_ccc(uint16_t ccc_handle){
    uint8_t val[2] = {0x01, 0x00}; // notifications
    esp_ble_gattc_write_char_descr(g_gattc_if, g_conn_id, ccc_handle,
                                   sizeof(val), val,
                                   ESP_GATT_WRITE_TYPE_RSP,
                                   ESP_GATT_AUTH_REQ_NONE);
}

/* ====== GATTC CB ====== */
static void gattc_cb(esp_gattc_cb_event_t e, esp_gatt_if_t gattc_if, esp_ble_gattc_cb_param_t* p)
{
    if (e == ESP_GATTC_REG_EVT) {
        g_gattc_if = gattc_if;
        esp_ble_gatt_set_local_mtu(247);
        (void)start_scan_safe(0);
        return;
    }

    switch (e) {
    case ESP_GATTC_OPEN_EVT:
        if (p->open.status == ESP_GATT_OK) {
            g_connecting = false;
            g_conn_id = p->open.conn_id;
            g_connected = true;
            ble_up = 1;
            reset_gatt_state();
            rx_reset();
            ESP_LOGI(TAG, "connected, conn_id=%u", g_conn_id);
            esp_ble_gattc_send_mtu_req(g_gattc_if, g_conn_id);
            esp_ble_gattc_search_service(g_gattc_if, g_conn_id, NULL);
        } else {
            ESP_LOGW(TAG, "open failed 0x%x; restart scan", p->open.status);
            g_connecting = false;
            ble_up = 0;
            vTaskDelay(pdMS_TO_TICKS(200));
            start_scan_safe(0);
        }
        break;

    case ESP_GATTC_CFG_MTU_EVT:
        if (p->cfg_mtu.mtu > 0) {
            g_mtu = p->cfg_mtu.mtu;
        }
        ESP_LOGI(TAG, "ATT_MTU=%u", g_mtu);
        break;

    case ESP_GATTC_SEARCH_RES_EVT:
        if (p->search_res.srvc_id.uuid.len == ESP_UUID_LEN_128) {
            const uint8_t* u = p->search_res.srvc_id.uuid.uuid.uuid128;
            if (memcmp(u, UWB_SVC_UUID_128, 16)==0 || memcmp(u, UWB_SVC_UUID_128_BE, 16)==0) {
                g_start_handle = p->search_res.start_handle;
                g_end_handle   = p->search_res.end_handle;
                ESP_LOGI(TAG, "svc found: 0x%04X..0x%04X", g_start_handle, g_end_handle);
            }
        }
        break;

    case ESP_GATTC_SEARCH_CMPL_EVT: {
        if (!g_start_handle || !g_end_handle){
            g_start_handle = 0x0001; g_end_handle = 0xFFFF;
            ESP_LOGW(TAG, "service not found by UUID, fallback range 0x%04X..0x%04X",
                     g_start_handle, g_end_handle);
        }

        bool have_data=false, have_cfg=false;

        /* UUID alapú keresés */
        {
            esp_gattc_char_elem_t chr[1]; uint16_t count=1;
            esp_bt_uuid_t cu = uuid128(UWB_DATA_UUID_128);
            if (esp_ble_gattc_get_char_by_uuid(g_gattc_if, g_conn_id,
                    g_start_handle, g_end_handle, cu, chr, &count) == ESP_GATT_OK && count) {
                g_data_h = chr[0].char_handle; have_data=true;
                ESP_LOGI(TAG, "DATA char=0x%04X", g_data_h);
            }
        }
        {
            esp_gattc_char_elem_t chr[1]; uint16_t count=1;
            esp_bt_uuid_t cu = uuid128(UWB_CFG_UUID_128);
            if (esp_ble_gattc_get_char_by_uuid(g_gattc_if, g_conn_id,
                    g_start_handle, g_end_handle, cu, chr, &count) == ESP_GATT_OK && count) {
                g_cfg_h = chr[0].char_handle; have_cfg=true;
                ESP_LOGI(TAG, "CFG  char=0x%04X", g_cfg_h);
            }
        }

        /* Fallback: tulajdonság alapján */
        if (!have_data || !have_cfg){
            uint16_t count=0;
            if (esp_ble_gattc_get_attr_count(g_gattc_if, g_conn_id, ESP_GATT_DB_CHARACTERISTIC,
                    g_start_handle, g_end_handle, 0, &count)==ESP_GATT_OK && count){
                esp_gattc_char_elem_t* list = calloc(count, sizeof(*list));
                if (list && esp_ble_gattc_get_all_char(g_gattc_if, g_conn_id,
                        g_start_handle, g_end_handle, list, &count, 0)==ESP_GATT_OK){
                    for (int i=0;i<count;i++){
                        uint8_t p2 = list[i].properties;
                        if (p2 & ESP_GATT_CHAR_PROP_BIT_NOTIFY){
                            if (!have_data && (p2 & ESP_GATT_CHAR_PROP_BIT_READ)){
                                g_data_h = list[i].char_handle; have_data=true;
                                ESP_LOGI(TAG,"DATA char(enum)=0x%04X", g_data_h);
                            } else if (!have_cfg && ((p2 & ESP_GATT_CHAR_PROP_BIT_WRITE) || (p2 & ESP_GATT_CHAR_PROP_BIT_WRITE_NR))){
                                g_cfg_h = list[i].char_handle; have_cfg=true;
                                ESP_LOGI(TAG,"CFG  char(enum)=0x%04X", g_cfg_h);
                            }
                        }
                    }
                }
                free(list);
            }
        }

        /* CCC és feliratkozás */
        if (g_data_h){
            esp_gattc_descr_elem_t dsc[1]; uint16_t count=1;
            if (esp_ble_gattc_get_descr_by_char_handle(g_gattc_if, g_conn_id, g_data_h,
                    uuid16(ESP_GATT_UUID_CHAR_CLIENT_CONFIG), dsc, &count)==ESP_GATT_OK && count) {
                g_data_ccc_h = dsc[0].handle;
                esp_ble_gattc_register_for_notify(g_gattc_if, g_peer_bda, g_data_h);
                enable_ccc(g_data_ccc_h);
            }
        }
        if (g_cfg_h){
            esp_gattc_descr_elem_t dsc[1]; uint16_t count=1;
            if (esp_ble_gattc_get_descr_by_char_handle(g_gattc_if, g_conn_id, g_cfg_h,
                    uuid16(ESP_GATT_UUID_CHAR_CLIENT_CONFIG), dsc, &count)==ESP_GATT_OK && count) {
                g_cfg_ccc_h = dsc[0].handle;
                esp_ble_gattc_register_for_notify(g_gattc_if, g_peer_bda, g_cfg_h);
                enable_ccc(g_cfg_ccc_h);
            }
        }

        if (!g_data_h || !g_cfg_h){
            ESP_LOGW(TAG, "char lookup incomplete; disconnect");
            esp_ble_gattc_close(g_gattc_if, g_conn_id);
        }
        break;
    }

    case ESP_GATTC_NOTIFY_EVT: {
        bool from_cfg = (p->notify.handle == g_cfg_h);
        if (from_cfg) handle_cfg_notify(p->notify.value, p->notify.value_len);
        if (g_cb1) g_cb1(p->notify.value, p->notify.value_len, from_cfg);
        if (g_cb2) g_cb2(p->notify.value, p->notify.value_len, from_cfg);
        break;
    }

    case ESP_GATTC_WRITE_DESCR_EVT:
        ESP_LOGI(TAG, "CCC write 0x%04X rc=0x%x", p->write.handle, p->write.status);
        break;

    case ESP_GATTC_WRITE_CHAR_EVT:
        ESP_LOGI(TAG, "WRITE char 0x%04X rc=0x%x", p->write.handle, p->write.status);
        break;

    case ESP_GATTC_CLOSE_EVT:
        ESP_LOGW(TAG, "gattc closed; status=0x%x", p->close.status);
        g_connected = false;
        g_connecting = false;
        ble_up = 0;
        rx_reset();
        reset_gatt_state();
        vTaskDelay(pdMS_TO_TICKS(100));
        start_scan_safe(0);
        break;

    case ESP_GATTC_DISCONNECT_EVT:
        ESP_LOGW(TAG, "disconnected; reason=0x%x", p->disconnect.reason);
        g_connected = false;
        g_connecting = false;
        ble_up = 0;
        rx_reset();
        reset_gatt_state();
        vTaskDelay(pdMS_TO_TICKS(100));
        start_scan_safe(0);
        break;

    default: break;
    }
}

/* ====== SET/GET küldők ====== */
static inline uint16_t max_write_payload(void){
    return (g_mtu > 7) ? (g_mtu - 7) : 0; /* ATT header 3 + ATT op + egyebek -> egyszerű kalkul */
}


esp_err_t ble_send_get(uint16_t req_id)
{
    if (!g_connected || !g_cfg_h) return ESP_ERR_INVALID_STATE;
    /* ver=1, cmd=GET(0x02), req_id, n_tlv=0 */
    uint8_t pkt[5] = {1, OP_GET, (uint8_t)(req_id>>8), (uint8_t)req_id, 0};
    esp_err_t er = esp_ble_gattc_write_char(g_gattc_if, g_conn_id, g_cfg_h,
                                            sizeof(pkt), pkt,
                                            ESP_GATT_WRITE_TYPE_RSP,
                                            ESP_GATT_AUTH_REQ_NONE);
    return er;
}

esp_err_t ble_send_set(uint16_t req_id, const uint8_t* tlv, uint16_t len)
{
    if (!g_connected || !g_cfg_h) return ESP_ERR_INVALID_STATE;
    if (len > max_write_payload()) return ESP_ERR_INVALID_SIZE;

    uint8_t hdr[5] = {1, 0x01, (uint8_t)(req_id>>8), (uint8_t)req_id, 0xFF /* n_tlv (nem kötelező) */};
    uint16_t total = sizeof(hdr) + len;

    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) return ESP_ERR_NO_MEM;
    memcpy(buf, hdr, 5);
    if (tlv && len) memcpy(buf+5, tlv, len);

    esp_err_t er = esp_ble_gattc_write_char(g_gattc_if, g_conn_id, g_cfg_h,
                                            total, buf,
                                            ESP_GATT_WRITE_TYPE_RSP,
                                            ESP_GATT_AUTH_REQ_NONE);
    free(buf);
    ESP_LOGI(TAG, "SEND SET req=0x%04X len=%u -> 0x%x", req_id, len, er);
    return er;
}

esp_err_t ble_cfg_write_raw(const uint8_t *data, uint16_t len)
{
    if (!g_connected || !g_cfg_h) {
        return ESP_ERR_INVALID_STATE;
    }

    return esp_ble_gattc_write_char(g_gattc_if,
                                    g_conn_id,
                                    g_cfg_h,
                                    len,
                                    (uint8_t *)data,
                                    ESP_GATT_WRITE_TYPE_RSP,
                                    ESP_GATT_AUTH_REQ_NONE);
}

