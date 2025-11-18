#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "lwip/ip4_addr.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_eth_mac_esp.h"
#include "esp_eth_phy.h"
#include "esp_rom_sys.h"
#include "ethernet.h"
#include "globals.h"

#define TAG                 "eth"
#define PHY_ADDR            0        // ha nem jó, próbáld 1-et
#define PHY_RESET_GPIO      (-1)     // ha van külön reset, ide tedd a GPIO-t
#define PHY_PWR_EN_GPIO     12       // OLIMEX: PHY/VDD33 enable
#define SMI_MDC_GPIO        23
#define SMI_MDIO_GPIO       18

static esp_netif_t* s_eth = NULL;

static void on_eth_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    switch (id) {
        case ETHERNET_EVENT_CONNECTED:    ESP_LOGI(TAG, "link up"); break;
        case ETHERNET_EVENT_DISCONNECTED: ESP_LOGW(TAG, "link down"); break;
        case ETHERNET_EVENT_START:        ESP_LOGI(TAG, "start"); break;
        case ETHERNET_EVENT_STOP:         ESP_LOGI(TAG, "stop"); break;
        default: break;
    }
}

static void apply_static_ip(esp_netif_t *netif)
{
    esp_netif_dhcpc_stop(netif);

    esp_netif_ip_info_t ipi = {0};
    ip4_addr_copy(ipi.ip,      NET.ip);
    ip4_addr_copy(ipi.gw,      NET.gw);
    ip4_addr_copy(ipi.netmask, NET.mask);
    ESP_ERROR_CHECK(esp_netif_set_ip_info(netif, &ipi));

    esp_netif_dns_info_t d = {0};
    d.ip.type = ESP_IPADDR_TYPE_V4;              // <-- ez fontos
    ip4_addr_copy(d.ip.u_addr.ip4, NET.dns1);
    ESP_ERROR_CHECK(esp_netif_set_dns_info(netif, ESP_NETIF_DNS_MAIN, &d));
    ip4_addr_copy(d.ip.u_addr.ip4, NET.dns2);
    ESP_ERROR_CHECK(esp_netif_set_dns_info(netif, ESP_NETIF_DNS_BACKUP, &d));
}

static void on_got_ip(void *arg, esp_event_base_t base, int32_t id, void *data) {
    const ip_event_got_ip_t *e = (const ip_event_got_ip_t *)data;
    esp_netif_ip_info_t ip;
    esp_netif_get_ip_info(esp_netif_get_handle_from_ifkey("ETH_DEF"), &ip);

    ESP_LOGI(TAG, "IP: " IPSTR "  NM: " IPSTR "  GW: " IPSTR,
             IP2STR(&e->ip_info.ip), IP2STR(&e->ip_info.netmask), IP2STR(&e->ip_info.gw));
    ESP_LOGI(TAG, "ip=%s mask=%s gw=%s",
         ip4addr_ntoa((const ip4_addr_t *)&ip.ip),
         ip4addr_ntoa((const ip4_addr_t *)&ip.netmask),
         ip4addr_ntoa((const ip4_addr_t *)&ip.gw));
}

static void phy_power_enable(void) {
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << PHY_PWR_EN_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = 0,
        .pull_down_en = 0,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&io);
    gpio_set_level(PHY_PWR_EN_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(20));
}

esp_err_t ethernet_init(ethernet_ctx_t *ctx) {
    if (!ctx) return ESP_ERR_INVALID_ARG;
    memset(ctx, 0, sizeof(*ctx));

    // PoE táp felfutás
    phy_power_enable();
    esp_rom_delay_us(300000); // 300 ms késleltetés indulás előtt

    // netif
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    ctx->netif = esp_netif_new(&netif_cfg);
    ESP_ERROR_CHECK(esp_netif_set_default_netif(ctx->netif));

    // események
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &on_eth_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT,  IP_EVENT_ETH_GOT_IP, &on_got_ip, NULL));

    // MAC/PHY
    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.phy_addr = PHY_ADDR;
    phy_cfg.reset_gpio_num = PHY_RESET_GPIO;

    eth_esp32_emac_config_t emac_hw = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    emac_hw.smi_gpio.mdc_num  = SMI_MDC_GPIO;
    emac_hw.smi_gpio.mdio_num = SMI_MDIO_GPIO;
    // RMII clock módot és a 50 MHz kimenetet (GPIO17) a menuconfig kezeli.

    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&emac_hw, &mac_cfg);
    esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_cfg);

    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_cfg, &ctx->handle));

    // glue
    ESP_ERROR_CHECK(esp_netif_attach(ctx->netif, esp_eth_new_netif_glue(ctx->handle)));

    apply_static_ip(ctx->netif);

    // start
    ESP_ERROR_CHECK(esp_eth_start(ctx->handle));
    ESP_LOGI(TAG, "init done");

    return ESP_OK;
}

void ethernet_deinit(ethernet_ctx_t *ctx) {
    if (!ctx || !ctx->handle) return;
    esp_eth_stop(ctx->handle);
    esp_eth_driver_uninstall(ctx->handle);
    ctx->handle = NULL;
    if (ctx->netif) {
        esp_netif_destroy(ctx->netif);
        ctx->netif = NULL;
    }
}
