// components/webserver/web_stats.c

#include "esp_http_server.h"
#include "esp_log.h"

static const char *TAG = "WEB_STATS";

// Itt lesznek majd a /api/stats mérések, most csak stubbok, hogy forduljon.
void web_stats_init(void)
{
    ESP_LOGI(TAG, "web_stats_init()");
    // TODO: itt tudsz majd időzítőt, statisztika-gyűjtést elindítani
}

// Regisztráljuk a /stats HTML oldalt és a /api/stats JSON API-t
static esp_err_t web_stats_page(httpd_req_t *req)
{
    // Egyelőre csak egy sima szöveg, amíg be nem másolod a kész HTML-t
    const char *html = "<html><body><h1>Stats page placeholder</h1></body></html>";
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_sendstr(req, html);
}

static esp_err_t web_stats_api(httpd_req_t *req)
{
    const char *json = "{\"ok\":true,\"msg\":\"stats placeholder\"}\n";
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, json);
}

void web_stats_register_handlers(httpd_handle_t h)
{
    ESP_LOGI(TAG, "web_stats_register_handlers()");

    httpd_uri_t uri_stats_page = {
        .uri      = "/stats",
        .method   = HTTP_GET,
        .handler  = web_stats_page,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(h, &uri_stats_page);

    httpd_uri_t uri_stats_api = {
        .uri      = "/api/stats",
        .method   = HTTP_GET,
        .handler  = web_stats_api,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(h, &uri_stats_api);
}
