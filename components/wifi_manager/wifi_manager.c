#include <string.h>
#include <stdbool.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "lwip/ip4_addr.h"

#include "wifi_manager.h"

#define TAG "wifi_manager"
#define WIFI_CFG_NS  "wifi_cfg"
#define WIFI_CFG_KEY "sta_cfg"

static wifi_manager_config_t s_cfg = {
    .enabled = 0,
    .dhcp = 1,
    .ssid = "Hullam_144",
    .password = "Khjhjj11",
    .ip = "192.168.1.194",
    .mask = "255.255.255.0",
    .gw = "192.168.1.1",
    .dns1 = "1.1.1.1",
    .dns2 = "8.8.8.8",
};

static esp_netif_t *s_netif = NULL;
static bool s_event_handlers_registered = false;
static bool s_wifi_inited = false;
static bool s_started = false;
static bool s_connected = false;
static bool s_has_ip = false;
static char s_ip_str[16] = "0.0.0.0";

static esp_err_t cfg_load_from_nvs(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(WIFI_CFG_NS, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return err;
    }

    size_t sz = sizeof(s_cfg);
    err = nvs_get_blob(h, WIFI_CFG_KEY, &s_cfg, &sz);
    nvs_close(h);

    return err;
}

static esp_err_t cfg_save_to_nvs(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(WIFI_CFG_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_blob(h, WIFI_CFG_KEY, &s_cfg, sizeof(s_cfg));
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

static void apply_static_ip(void)
{
    if (!s_netif) return;

    if (s_cfg.dhcp) {
        esp_netif_dhcpc_start(s_netif);
        return;
    }

    esp_netif_dhcpc_stop(s_netif);

    esp_netif_ip_info_t ipi = {0};
    ip4addr_aton(s_cfg.ip,   &ipi.ip);
    ip4addr_aton(s_cfg.mask, &ipi.netmask);
    ip4addr_aton(s_cfg.gw,   &ipi.gw);
    esp_netif_set_ip_info(s_netif, &ipi);

    esp_netif_dns_info_t d = {0};
    d.ip.type = ESP_IPADDR_TYPE_V4;

    ip4addr_aton(s_cfg.dns1, &d.ip.u_addr.ip4);
    esp_netif_set_dns_info(s_netif, ESP_NETIF_DNS_MAIN, &d);

    ip4addr_aton(s_cfg.dns2, &d.ip.u_addr.ip4);
    esp_netif_set_dns_info(s_netif, ESP_NETIF_DNS_BACKUP, &d);
}

static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;
    (void)data;

    switch (id) {
        case WIFI_EVENT_STA_START:
            ESP_LOGI(TAG, "STA started");
            esp_wifi_connect();
            break;

        case WIFI_EVENT_STA_CONNECTED:
            s_connected = true;
            ESP_LOGI(TAG, "STA connected");
            break;

        case WIFI_EVENT_STA_DISCONNECTED:
            s_connected = false;
            s_has_ip = false;
            strncpy(s_ip_str, "0.0.0.0", sizeof(s_ip_str) - 1);
            s_ip_str[sizeof(s_ip_str) - 1] = 0;
            ESP_LOGW(TAG, "STA disconnected");
            if (s_started && s_cfg.enabled) {
                esp_wifi_connect();
            }
            break;

        default:
            break;
    }
}

static void on_wifi_got_ip(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;
    (void)id;

    const ip_event_got_ip_t *e = (const ip_event_got_ip_t *)data;
    s_has_ip = true;
    snprintf(s_ip_str, sizeof(s_ip_str), IPSTR, IP2STR(&e->ip_info.ip));

    if (s_netif) {
        esp_netif_set_default_netif(s_netif);
    }

    ESP_LOGI(TAG, "Wi-Fi IP: %s", s_ip_str);
}

static esp_err_t ensure_wifi_stack(void)
{
    if (s_wifi_inited) {
        return ESP_OK;
    }

    s_netif = esp_netif_create_default_wifi_sta();
    if (!s_netif) {
        return ESP_FAIL;
    }

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    if (!s_event_handlers_registered) {
        ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &on_wifi_event, NULL));
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &on_wifi_got_ip, NULL));
        s_event_handlers_registered = true;
    }

    s_wifi_inited = true;
    return ESP_OK;
}

esp_err_t wifi_manager_init(void)
{
    esp_err_t err = cfg_load_from_nvs();
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "no Wi-Fi config in NVS, using defaults");
    }

    return ensure_wifi_stack();
}

const wifi_manager_config_t* wifi_manager_get_config(void)
{
    return &s_cfg;
}


esp_err_t wifi_manager_set_config(const wifi_manager_config_t *cfg, bool keep_password_if_empty)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;

    wifi_manager_config_t tmp = *cfg;

    tmp.ssid[sizeof(tmp.ssid) - 1] = 0;
    tmp.password[sizeof(tmp.password) - 1] = 0;
    tmp.ip[sizeof(tmp.ip) - 1] = 0;
    tmp.mask[sizeof(tmp.mask) - 1] = 0;
    tmp.gw[sizeof(tmp.gw) - 1] = 0;
    tmp.dns1[sizeof(tmp.dns1) - 1] = 0;
    tmp.dns2[sizeof(tmp.dns2) - 1] = 0;

    if (keep_password_if_empty && tmp.password[0] == 0) {
        strncpy(tmp.password, s_cfg.password, sizeof(tmp.password) - 1);
        tmp.password[sizeof(tmp.password) - 1] = 0;
    }

    s_cfg = tmp;

    esp_err_t err = cfg_save_to_nvs();
    if (err != ESP_OK) {
        return err;
    }

    if (s_started) {
        wifi_manager_stop();
        if (wifi_manager_should_run()) {
            return wifi_manager_start();
        }
    }

    return ESP_OK;
}

bool wifi_manager_is_enabled(void)
{
    return s_cfg.enabled != 0;
}

bool wifi_manager_should_run(void)
{
    return (s_cfg.enabled != 0) && (s_cfg.ssid[0] != 0);
}

esp_err_t wifi_manager_start(void)
{
    if (!wifi_manager_should_run()) {
        return ESP_ERR_INVALID_STATE;
    }

    ESP_ERROR_CHECK(ensure_wifi_stack());

    wifi_config_t cfg = {0};
    strncpy((char *)cfg.sta.ssid, s_cfg.ssid, sizeof(cfg.sta.ssid) - 1);
    strncpy((char *)cfg.sta.password, s_cfg.password, sizeof(cfg.sta.password) - 1);
    cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    cfg.sta.pmf_cfg.capable = true;
    cfg.sta.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    apply_static_ip();
    esp_netif_set_default_netif(s_netif);
    esp_wifi_connect();

    s_started = true;
    return ESP_OK;
}

esp_err_t wifi_manager_stop(void)
{
    if (!s_wifi_inited || !s_started) {
        return ESP_OK;
    }

    esp_wifi_disconnect();
    esp_wifi_stop();

    s_started = false;
    s_connected = false;
    s_has_ip = false;
    strncpy(s_ip_str, "0.0.0.0", sizeof(s_ip_str) - 1);
    s_ip_str[sizeof(s_ip_str) - 1] = 0;

    return ESP_OK;
}

bool wifi_manager_is_started(void)
{
    return s_started;
}

bool wifi_manager_is_connected(void)
{
    return s_connected;
}

bool wifi_manager_has_ip(void)
{
    return s_has_ip;
}

const char* wifi_manager_get_ip_str(void)
{
    return s_ip_str;
}
