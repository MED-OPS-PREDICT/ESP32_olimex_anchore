// components/webserver/web_stats.c

#include "web_stats.h"
#include "esp_log.h"
#include "esp_http_server.h"

#include "esp_system.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_freertos_hooks.h"

#include <math.h>
#include <inttypes.h>
#include <stdio.h>

static const char *TAG = "WEB_STATS";

#define CORE_COUNT 2

/* =========================
 *  CPU terhelés (idle hook)
 * ========================= */

static volatile uint64_t s_idle_us[CORE_COUNT]      = {0, 0};
static volatile uint64_t s_idle_last_us[CORE_COUNT] = {0, 0};

static uint64_t s_prev_time_us = 0;
static uint64_t s_prev_idle_us[CORE_COUNT] = {0, 0};

static bool idle_hook_core0(void)
{
    uint64_t now  = esp_timer_get_time();
    uint64_t last = s_idle_last_us[0];
    if (last != 0) {
        s_idle_us[0] += (now - last);
    }
    s_idle_last_us[0] = now;
    return true;
}

static bool idle_hook_core1(void)
{
    uint64_t now  = esp_timer_get_time();
    uint64_t last = s_idle_last_us[1];
    if (last != 0) {
        s_idle_us[1] += (now - last);
    }
    s_idle_last_us[1] = now;
    return true;
}

/* 0..1 közötti átlag CPU load (összes mag) */
static float cpu_load_sample(void)
{
    uint64_t now_us = esp_timer_get_time();

    if (s_prev_time_us == 0) {
        s_prev_time_us = now_us;
        for (int i = 0; i < CORE_COUNT; ++i) {
            s_prev_idle_us[i] = s_idle_us[i];
        }
        return 0.0f;
    }

    uint64_t dt = now_us - s_prev_time_us;
    if (dt < 1000) {
        dt = 1000;
    }

    double sum   = 0.0;
    int    used  = 0;

    for (int i = 0; i < CORE_COUNT; ++i) {
        uint64_t idle_dt   = s_idle_us[i] - s_prev_idle_us[i];
        double   idle_frac = (double)idle_dt / (double)dt;
        double   load      = 1.0 - idle_frac;
        if (load < 0.0) load = 0.0;
        if (load > 1.0) load = 1.0;

        sum += load;
        used++;
        s_prev_idle_us[i] = s_idle_us[i];
    }

    s_prev_time_us = now_us;

    if (used == 0) return 0.0f;
    return (float)(sum / (double)used);
}

/* =========================
 *  INIT
 * ========================= */

void web_stats_init(void)
{
    ESP_LOGI(TAG, "web_stats_init()");

    // idle hook mindkét magra
    esp_register_freertos_idle_hook_for_cpu(&idle_hook_core0, 0);
    esp_register_freertos_idle_hook_for_cpu(&idle_hook_core1, 1);
}

/* =========================
 *  /api/stats handler
 * ========================= */

static esp_err_t web_stats_api(httpd_req_t *req)
{
    // uptime
    uint64_t now_us   = esp_timer_get_time();
    uint64_t uptime_ms = now_us / 1000ULL;
    uint64_t uptime_sec = uptime_ms / 1000ULL;

    // CPU load
    float load = cpu_load_sample();

    // chip / flash
    esp_chip_info_t chip;
    esp_chip_info(&chip);

    uint32_t flash_total = 0;
    (void)esp_flash_get_size(NULL, &flash_total);

    // heap
    uint32_t heap_free     = (uint32_t)esp_get_free_heap_size();
    uint32_t heap_min_free = (uint32_t)esp_get_minimum_free_heap_size();

    size_t int_free  = heap_caps_get_free_size(MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    size_t int_total = heap_caps_get_total_size(MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);

#ifdef MALLOC_CAP_SPIRAM
    size_t ps_free  = heap_caps_get_free_size(MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM);
    size_t ps_total = heap_caps_get_total_size(MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM);
#else
    size_t ps_free  = 0;
    size_t ps_total = 0;
#endif

    uint32_t int_used = (uint32_t)((int_total > int_free) ? (int_total - int_free) : 0);
    uint32_t ps_used  = (uint32_t)((ps_total > ps_free) ? (ps_total - ps_free) : 0);

    double loadF = (double)load;  // 0..1, ezt várja a frontend stat.cpu.load-ként

    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "{"
          "\"ts\":%" PRIu64 ","
          "\"uptime_ms\":%" PRIu64 ","
          "\"uptime_sec\":%" PRIu64 ","
          "\"cpu\":{"
            "\"mhz\":%u,"
            "\"cores\":2,"
            "\"load\":%.3f,"
            "\"cores_load\":[%u,%u],"
            "\"total\":%u"
          "},"
          "\"chip\":{"
            "\"model\":\"ESP32\","
            "\"cores\":%d,"
            "\"rev\":%d"
          "},"
          "\"flash\":{"
            "\"bytes\":%" PRIu32
          "},"
          "\"heap\":{"
            "\"free\":%" PRIu32 ","
            "\"min_free\":%" PRIu32 ","
            "\"int_free\":%" PRIu32 ","
            "\"int_total\":%" PRIu32 ","
            "\"int_used\":%" PRIu32 ","
            "\"psram_free\":%" PRIu32 ","
            "\"psram_total\":%" PRIu32 ","
            "\"psram_used\":%" PRIu32
          "}"
        "}\n",
        (unsigned long long)uptime_sec,          // ts
        (unsigned long long)uptime_ms,
        (unsigned long long)uptime_sec,
        (unsigned)CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
        loadF,
        (unsigned)lround(loadF * 100.0),
        (unsigned)lround(loadF * 100.0),
        (unsigned)lround(loadF * 100.0),
        chip.cores,
        chip.revision,
        (uint32_t)flash_total,
        heap_free,
        heap_min_free,
        (uint32_t)int_free,
        (uint32_t)int_total,
        int_used,
        (uint32_t)ps_free,
        (uint32_t)ps_total,
        ps_used
    );

    if (n < 0) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "fmt error");
    }

    // --- BLE KPI placeholder ---
    cJSON *js_ble = cJSON_CreateObject();
    if (js_ble) {
        cJSON_AddNumberToObject(js_ble, "rx_rate",   0.0);
        cJSON_AddNumberToObject(js_ble, "tx_rate",   0.0);
        cJSON_AddNumberToObject(js_ble, "err_rate",  0.0);
        cJSON_AddNumberToObject(js_ble, "rx_total",  0);
        cJSON_AddNumberToObject(js_ble, "tx_total",  0);
        cJSON_AddNumberToObject(js_ble, "err_total", 0);
        cJSON_AddItemToObject(root, "ble", js_ble);
    }

    // --- ETH KPI placeholder ---
    cJSON *js_eth = cJSON_CreateObject();
    if (js_eth) {
        cJSON_AddNumberToObject(js_eth, "rx_rate",   0.0);
        cJSON_AddNumberToObject(js_eth, "tx_rate",   0.0);
        cJSON_AddNumberToObject(js_eth, "err_rate",  0.0);
        cJSON_AddNumberToObject(js_eth, "rx_total",  0);
        cJSON_AddNumberToObject(js_eth, "tx_total",  0);
        cJSON_AddNumberToObject(js_eth, "err_total", 0);
        cJSON_AddItemToObject(root, "eth", js_eth);
    }

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, n);
}

/* csak /api/stats-ot regisztráljuk – /stats HTML már megvan máshol */
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
