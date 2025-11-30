// web_stats.cpp
#include <math.h>
#include <string.h>
#include <stdio.h>

#include "esp_system.h"
#include "esp_chip_info.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_freertos_hooks.h"
#include "esp_log.h"
#include "esp_flash.h"

#include "esp_http_server.h"

#include "web_stats.h"
#include "webserver.hpp"      // add_cors, add_no_cache, send_file ha itt akarod használni

static const char *TAG_STATS = "WEB_STATS";

/* ===== Idle hook + CPU load ===== */

static volatile uint64_t s_idle_us[2]      = {0,0};
static volatile uint64_t s_idle_last_us[2] = {0,0};
static uint64_t          s_prev_time_us    = 0;
static uint64_t          s_prev_idle_us[2] = {0,0};

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

void web_stats_init(void)
{
    static bool inited = false;
    if (inited) return;
    inited = true;

    ESP_LOGI(TAG_STATS, "registering idle hooks for CPU load");
    esp_register_freertos_idle_hook_for_cpu(&idle_hook_core0, 0);
    esp_register_freertos_idle_hook_for_cpu(&idle_hook_core1, 1);
}

/* ====== /api/stats JSON ====== */

static esp_err_t api_stats_get(httpd_req_t *req)
{
    add_cors(req);
    add_no_cache(req);

    uint64_t now_us = esp_timer_get_time();
    uint64_t up_ms  = now_us / 1000ULL;

    double core_load[2] = {0.0, 0.0};

    if (s_prev_time_us == 0) {
        s_prev_time_us    = now_us;
        s_prev_idle_us[0] = s_idle_us[0];
        s_prev_idle_us[1] = s_idle_us[1];
    } else {
        uint64_t dt = now_us - s_prev_time_us;
        if (dt < 1000) dt = 1000;

        for (int i = 0; i < 2; ++i) {
            uint64_t idle_dt  = s_idle_us[i] - s_prev_idle_us[i];
            double   idle_frac= (double)idle_dt / (double)dt;
            double   load     = 1.0 - idle_frac;
            if (load < 0.0) load = 0.0;
            if (load > 1.0) load = 1.0;
            core_load[i] = load;
        }

        s_prev_time_us    = now_us;
        s_prev_idle_us[0] = s_idle_us[0];
        s_prev_idle_us[1] = s_idle_us[1];
    }

    uint32_t load0 = (uint32_t)lround(core_load[0] * 100.0);
    uint32_t load1 = (uint32_t)lround(core_load[1] * 100.0);
    uint32_t loadT = (uint32_t)lround(((core_load[0] + core_load[1]) / 2.0) * 100.0);

    esp_chip_info_t chip;
    esp_chip_info(&chip);

    uint32_t flash_total = 0;
    esp_flash_get_size(NULL, &flash_total);

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

    uint64_t up_sec = up_ms / 1000ULL;
    double   loadF  = ((double)loadT) / 100.0;  // 0..1 – ezt várja a frontend cpu.load-ként

    char buf[1024];
    int n = snprintf(buf, sizeof(buf),
        "{"
          "\"ts\":%" PRIu64 ","              // csak a böngésző órájához, lehet up_sec is
          "\"uptime_ms\":%" PRIu64 ","
          "\"uptime_sec\":%" PRIu64 ","      // EZT használja a web_stats.html
          "\"cpu\":{"
            "\"mhz\":%u,"
            "\"cores\":2,"
            "\"load\":%.3f,"                 // 0..1 – donut + KPI ehhez igazodik
            "\"cores_load\":[%u,%u],"
            "\"total\":%u"
          "},"
          "\"chip\":{"
            "\"model\":\"ESP32\","
            "\"cores\":%d,"
            "\"rev\":%d"
          "},"
          "\"flash\":{"
            "\"bytes\":%u"
          "},"
          "\"heap\":{"
            "\"free\":%u,"
            "\"min_free\":%u,"
            "\"int_free\":%u,"
            "\"int_total\":%u,"
            "\"int_used\":%u,"
            "\"psram_free\":%u,"
            "\"psram_total\":%u,"
            "\"psram_used\":%u"
          "}"
        "}\n",
        (unsigned long long)up_sec,                // ts
        (unsigned long long)up_ms,                 // uptime_ms
        (unsigned long long)up_sec,                // uptime_sec
        (unsigned)CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ, // mhz
        loadF,                                     // cpu.load (0..1)
        (unsigned)load0,
        (unsigned)load1,
        (unsigned)loadT,
        chip.cores,
        chip.revision,
        (unsigned)flash_total,
        heap_free,
        heap_min_free,
        (unsigned)int_free,
        (unsigned)int_total,
        (unsigned)(int_total - int_free),
        (unsigned)ps_free,
        (unsigned)ps_total,
        (unsigned)(ps_total - ps_free)
    );

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, n);
}


/* ====== /stats HTML oldal (SPIFFS-ből) ====== */

static esp_err_t stats_page_get(httpd_req_t *req)
{
    // itt vagy közvetlenül streamelsz SPIFFS-ből, vagy használod a már meglévő send_file-t:
    return send_file(req, "/spiffs/web_stats.html", "text/html");
}

/* ====== Route regisztrálás ====== */

void web_stats_register_handlers(httpd_handle_t server)
{
    httpd_uri_t u{};

    // HTML
    u.method  = HTTP_GET;
    u.uri     = "/stats";
    u.handler = stats_page_get;
    httpd_register_uri_handler(server, &u);

    // JSON
    httpd_uri_t s{};
    s.method   = HTTP_GET;
    s.uri      = "/api/stats";
    s.handler  = api_stats_get;
    httpd_register_uri_handler(server, &s);

    ESP_LOGI(TAG_STATS, "stats handlers registered");
}
