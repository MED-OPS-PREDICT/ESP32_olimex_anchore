#include "globals.h"
#include "lwip/ip4_addr.h"
#include "nvs_flash.h"
#include "nvs.h"

net_config_t NET;
ips_config_t IPS;
volatile int eth_up = 0;

void globals_init(void)
{
    bool loaded = false;
    nvs_handle_t h;
    esp_err_t r = nvs_open("netcfg", NVS_READONLY, &h);   // <<< ugyanaz a namespace, mint mentéskor

    if (r == ESP_OK) {
        uint32_t ip, gw, msk, dns1, dns2;

        if (nvs_get_u32(h, "ip",   &ip)   == ESP_OK &&
            nvs_get_u32(h, "gw",   &gw)   == ESP_OK &&
            nvs_get_u32(h, "msk",  &msk)  == ESP_OK &&
            nvs_get_u32(h, "dns1", &dns1) == ESP_OK &&
            nvs_get_u32(h, "dns2", &dns2) == ESP_OK)
        {
            NET.ip.addr      = ip;
            NET.gw.addr      = gw;
            NET.mask.addr    = msk;
            NET.dns1.addr    = dns1;
            NET.dns2.addr    = dns2;
            loaded = true;
        }

        nvs_close(h);
    }

    if (!loaded) {
        // csak akkor default, ha nincs érvényes NVS konfig
        IP4_ADDR(&NET.ip,   192,168,0,191);
        IP4_ADDR(&NET.gw,   192,168,0,1);
        IP4_ADDR(&NET.mask, 255,255,255,0);
        IP4_ADDR(&NET.dns1, 1,1,1,1);
        IP4_ADDR(&NET.dns2, 8,8,8,8);
    }

    NET.udp_port = 12345;
    NET.use_dhcp = 0;

    /* IPS defaultok maradhatnak, amíg nem viszed őket is NVS-be */
    IPS.gw_id = 1;
    IPS.hb_ms = 1000;
    IP4_ADDR(&IPS.dest[0].dest_ip, 192,168,0,172);
    IPS.dest[0].dest_port = 60000;
    IPS.dest[0].enabled   = 1;

    IP4_ADDR(&IPS.dest[1].dest_ip, 0,0,0,0);
    IPS.dest[1].dest_port = 0;
    IPS.dest[1].enabled   = 0;

    IP4_ADDR(&IPS.dest[2].dest_ip, 0,0,0,0);
    IPS.dest[2].dest_port = 0;
    IPS.dest[2].enabled   = 0;
}

status_t g_status = { "A1", 1, 0.0f, 0.0f, ST_UNKNOWN };

uint8_t g_hb_status = 0;
uint32_t g_hb_uptime = 0;
uint16_t g_hb_sync_ms = 0;
char g_hb_text[96] = "Anchor állapot: ismeretlen";
char g_hb_level[16] = "warn";