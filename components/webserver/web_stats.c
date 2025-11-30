// web_stats.c

#include "web_stats.h"
#include "esp_log.h"
#include "esp_http_server.h"

#include "esp_system.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_freertos_hooks.h"   // idle hook
#include <math.h>
#include "cJSON.h"

static const char *TAG = "WEB_STATS";

/* =========================
 *  CPU TERHELÉS (per mag)
 * =========================
 * A FreeRTOS idle hook-ban mérjük az idle időt mikroszekundumban.
 * /api/stats híváskor differenciáljuk → load = 1 - idle_dt / wall_dt.
 */

#define CORE_COUNT 2

static volatile uint64_t s_idle_us[CORE_COUNT]      = {0,0};
static volatile uint64_t s_idle_last_us[CORE_COUNT] = {0,0};

static uint64_t s_prev_time_us = 0;
static uint64_t s_prev_idle_us[CORE_COUNT] = {0,0};

static bool idle_hook_core0(void)
{
    uint64_t now = esp_timer_get_time();
    uint64_t last = s_idle_last_us[0];
    if (last != 0) {
        s_idle_us[0] += (now - last);
    }
    s_idle_last_us[0] = now;
    return true;    // maradjon regisztrálva
}

static bool idle_hook_core1(void)
{
    uint64_t now = esp_timer_get_time();
    uint64_t last = s_idle_last_us[1];
    if (last != 0) {
        s_idle_us[1] += (now - last);
    }
    s_idle_last_us[1] = now;
    return true;
}

/* CPU load 0..1 között (összes mag átlaga) */
static float cpu_load_sample(void)
{
    uint64_t now_us = esp_timer_get_time();

    if (s_prev_time_us == 0) {
        // első hívás – init, visszaadunk 0-t
        s_prev_time_us = now_us;
        for (int i = 0; i < CORE_COUNT; ++i) {
            s_prev_idle_us[i] = s_idle_us[i];
        }
        return 0.0f;
    }

    uint64_t dt = now_us - s_prev_time_us;
    if (dt < 1000) dt = 1000;  // védelem

    double sum = 0.0;
    int active = 0;

    for (int i = 0; i < CORE_COUNT; ++i) {
        uint64_t idle_dt = s_idle_us[i] - s_prev_idle_us[i];
        double idle_frac = (double)idle_dt / (double)dt;
        double load = 1.0 - idle_frac;
        if (load < 0.0) load = 0.0;
        if (load > 1.0) load = 1.0;
        sum += load;
        active++;
        s_prev_idle_us[i] = s_idle_us[i];
    }

    s_prev_time_us = now_us;

    if (active == 0) return 0.0f;
    return (float)(sum / (double)active);   // 0..1
}

/* =========================
 *  INIT
 * ========================= */

void web_stats_init(void)
{
    ESP_LOGI(TAG, "web_stats_init()");

    // idle hook regisztrálása mindkét magra
    (void)esp_register_freertos_idle_hook_for_cpu(&idle_hook_core0, 0);
    (void)esp_register_freertos_idle_hook_for_cpu(&idle_hook_core1, 1);
}

/* =========================
 *  /api/stats handler
 * ========================= */

static esp_err_t web_stats_api(httpd_req_t *req)
{
    esp_err_t res = ESP_OK;

    // uptime másodpercben (boot óta)
    uint64_t now_us = esp_timer_get_time();
    uint64_t uptime_sec = now_us / 1000000ULL;

    // szabad heap
    size_t heap_free = esp_get_free_heap_size();
    size_t heap_min_free = esp_get_minimum_free_heap_size();

    // CPU load 0..1 (összes mag átlaga)
    float load = cpu_load_sample();

    // JSON gyártás
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OOM");
    }

    // Ha nincs valódi RTC, a ts mezőt hagyhatjuk 0-nak,
    // így a frontend a current time-ot használja.
    cJSON_AddNumberToObject(root, "ts", 0);
    cJSON_AddNumberToObject(root, "uptime_sec", (double)uptime_sec);

    // CPU objektum
    cJSON *cpu = cJSON_CreateObject();
    if (cpu) {
        cJSON_AddNumberToObject(cpu, "load", (double)load);  // 0..1 – ezt várja a web_stats.html

        // opcionális, ha később per-core kellene
        cJSON *cores_arr = cJSON_CreateArray();
        if (cores_arr) {
            for (int i = 0; i < CORE_COUNT; ++i) {
                cJSON_AddItemToArray(cores_arr, cJSON_CreateNumber((double)load));
            }
            cJSON_AddItemToObject(cpu, "cores_load", cores_arr);
        }
        cJSON_AddItemToObject(root, "cpu", cpu);
    }

    // Heap objektum
    cJSON *heap = cJSON_CreateObject();
    if (heap) {
        cJSON_AddNumberToObject(heap, "free", (double)heap_free);
        cJSON_AddNumberToObject(heap, "min_free", (double)heap_min_free);

        // belső heap, psram – részletesebb stat
        size_t int_free  = heap_caps_get_free_size(MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
        size_t int_total = heap_caps_get_total_size(MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
        cJSON_AddNumberToObject(heap, "int_free",  (double)int_free);
        cJSON_AddNumberToObject(heap, "int_total", (double)int_total);
        cJSON_AddNumberToObject(heap, "int_used",
                                (double)(int_total > int_free ? int_total - int_free : 0));

#ifdef MALLOC_CAP_SPIRAM
        size_t ps_free  = heap_caps_get_free_size(MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM);
        size_t ps_total = heap_caps_get_total_size(MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM);
        cJSON_AddNumberToObject(heap, "psram_free",  (double)ps_free);
        cJSON_AddNumberToObject(heap, "psram_total", (double)ps_total);
        cJSON_AddNumberToObject(heap, "psram_used",
                                (double)(ps_total > ps_free ? ps_total - ps_free : 0));
#else
        cJSON_AddNumberToObject(heap, "psram_free",  0);
        cJSON_AddNumberToObject(heap, "psram_total", 0);
        cJSON_AddNumberToObject(heap, "psram_used",  0);
#endif

        cJSON_AddItemToObject(root, "heap", heap);
    }

    // BLE stat placeholder – itt tudod összekötni a saját számlálóiddal
    cJSON *ble = cJSON_CreateObject();
    if (ble) {
        cJSON_AddNumberToObject(ble, "rx_rate",  0.0);
        cJSON_AddNumberToObject(ble, "tx_rate",  0.0);
        cJSON_AddNumberToObject(ble, "rx_total", 0);
        cJSON_AddNumberToObject(ble, "tx_total", 0);
        cJSON_AddNumberToObject(ble, "err_rate", 0.0);
        cJSON_AddNumberToObject(ble, "err_total", 0);
        cJSON_AddItemToObject(root, "ble", ble);
    }

    // ETH stat placeholder – itt tudod összekötni a saját számlálóiddal
    cJSON *eth = cJSON_CreateObject();
    if (eth) {
        cJSON_AddNumberToObject(eth, "rx_rate",  0.0);
        cJSON_AddNumberToObject(eth, "tx_rate",  0.0);
        cJSON_AddNumberToObject(eth, "rx_total", 0);
        cJSON_AddNumberToObject(eth, "tx_total", 0);
        cJSON_AddNumberToObject(eth, "err_rate", 0.0);
        cJSON_AddNumberToObject(eth, "err_total", 0);
        cJSON_AddItemToObject(root, "eth", eth);
    }

    // Link állapot – most mindent "ok"-ra tesszük; ha van valós infód, ide kösd be
    cJSON *link = cJSON_CreateObject();
    if (link) {
        cJSON_AddBoolToObject(link, "ble_up",  true);
        cJSON_AddBoolToObject(link, "eth_up",  true);
        cJSON_AddBoolToObject(link, "main_up", true);
        cJSON_AddItemToObject(root, "link", link);
    }

    // Üres idősor a grafikonhoz – ha van mintavételed, ide appendelj
    cJSON *samples = cJSON_CreateArray();
    if (samples) {
        // Példának hagyjuk üresen; a frontend ezt is kezeli
        cJSON_AddItemToObject(root, "samples", samples);
    }

    // Üres last_ble / last_eth listák – a táblákhoz
    cJSON *last_ble = cJSON_CreateArray();
    if (last_ble) {
        // ha vannak logolt BLE csomagok, ide pushold őket:
        // { "ts": ms, "rssi": -70, "len": 32, "meta": "tag=1234" }
        cJSON_AddItemToObject(root, "last_ble", last_ble);
    }

    cJSON *last_eth = cJSON_CreateArray();
    if (last_eth) {
        // ha vannak logolt ETH csomagok, ide pushold őket:
        // { "ts": ms, "src": "10.0.0.10:6000", "len": 64, "meta": "zone=1" }
        cJSON_AddItemToObject(root, "last_eth", last_eth);
    }

    // JSON stringgé alakítás és kiküldés
    char *json_str = cJSON_PrintUnformatted(root);
    if (!json_str) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON error");
    }

    httpd_resp_set_type(req, "application/json");
    res = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    cJSON_free(json_str);
    cJSON_Delete(root);

    return res;
}

/* Csak /api/stats regisztrálása */

void web_stats_register_handlers(httpd_handle_t h)
{
    ESP_LOGI(TAG, "web_stats_register_handlers()");

    httpd_uri_t uri_stats_api = {
        .uri      = "/api/stats",
        .method   = HTTP_GET,
        .handler  = web_stats_api,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(h, &uri_stats_api);
}
