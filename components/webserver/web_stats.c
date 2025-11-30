// web_stats.c

#include "web_stats.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_chip_info.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "cJSON.h"

static const char *TAG = "WEB_STATS";

static char *human_ms(uint64_t ms)
{
    uint64_t s = ms/1000ULL; uint64_t d = s/86400ULL; s%=86400ULL;
    uint64_t h = s/3600ULL; s%=3600ULL;
    uint64_t m = s/60ULL;   s%=60ULL;

    static char buf[64];
    if (d)
        snprintf(buf,sizeof(buf),"%llud %02lluh %02llum %02llus",
                 (unsigned long long)d,(unsigned long long)h,
                 (unsigned long long)m,(unsigned long long)s);
    else
        snprintf(buf,sizeof(buf),"%02lluh %02llum %02llus",
                 (unsigned long long)h,(unsigned long long)m,(unsigned long long)s);
    return buf;
}

static esp_err_t web_stats_api(httpd_req_t *req)
{
    uint64_t now_us   = esp_timer_get_time();
    uint64_t up_ms    = now_us/1000ULL;

    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_FAIL;

    // uptime
    cJSON_AddNumberToObject(root, "uptime_ms", up_ms);
    cJSON_AddStringToObject(root, "uptime_human", human_ms(up_ms));

    // chip
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    cJSON *chip_o = cJSON_CreateObject();
    cJSON_AddStringToObject(chip_o, "model", "ESP32");
    cJSON_AddNumberToObject(chip_o, "cores", chip.cores);
    cJSON_AddNumberToObject(chip_o, "rev",   chip.revision);
    cJSON_AddItemToObject(root, "chip", chip_o);

    // CPU – ha nincs idle-hook, adj vissza csak frekit / magok számát
    cJSON *cpu_o = cJSON_CreateObject();
    cJSON_AddNumberToObject(cpu_o, "mhz",   (int)getCpuFrequencyMhz());
    cJSON_AddNumberToObject(cpu_o, "cores", 2);
    cJSON *cores = cJSON_AddArrayToObject(cpu_o, "cores_load");
    cJSON_AddItemToArray(cores, cJSON_CreateNumber(0));   // core0 %
    cJSON_AddItemToArray(cores, cJSON_CreateNumber(0));   // core1 %
    cJSON_AddNumberToObject(cpu_o, "total", 0);
    cJSON_AddItemToObject(root, "cpu", cpu_o);

    // heap
    uint32_t heap_free     = esp_get_free_heap_size();
    uint32_t heap_min_free = esp_get_minimum_free_heap_size();
    cJSON *heap_o = cJSON_CreateObject();
    cJSON_AddNumberToObject(heap_o, "free",     heap_free);
    cJSON_AddNumberToObject(heap_o, "min_free", heap_min_free);

    size_t int_free  = heap_caps_get_free_size(MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    size_t int_total = heap_caps_get_total_size(MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    cJSON_AddNumberToObject(heap_o, "int_free",  int_free);
    cJSON_AddNumberToObject(heap_o, "int_total", int_total);
    cJSON_AddNumberToObject(heap_o, "int_used",  int_total - int_free);

    cJSON_AddItemToObject(root, "heap", heap_o);

    // Ethernet – itt használd a saját esp_eth / netif adataidat
    cJSON *eth_o = cJSON_CreateObject();
    cJSON_AddBoolToObject(eth_o, "connected", false);
    cJSON_AddBoolToObject(eth_o, "link_up",   false);
    cJSON_AddNumberToObject(eth_o, "speed_mbps", 0);
    cJSON_AddBoolToObject(eth_o, "full_duplex", false);
    cJSON_AddStringToObject(eth_o, "ip",  "");
    cJSON_AddStringToObject(eth_o, "mac", "");
    cJSON_AddItemToObject(root, "eth", eth_o);

    // UWB / anchors / tags – itt tudod ugyanúgy feltölteni,
    // ahogy a fill_sysmon() csinálja az Arduino-s projektben,
    // a saját pktlog / ast / tstat struktúráidból.

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) return ESP_FAIL;

    httpd_resp_set_type(req, "application/json");
    esp_err_t res = httpd_resp_sendstr(req, json);
    free(json);
    return res;
}

void web_stats_init(void)
{
    ESP_LOGI(TAG, "web_stats_init()");
}

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
