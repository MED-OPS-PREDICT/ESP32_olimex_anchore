#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"

#include "esp_log.h"
#include "ble_logger.h"
#include "aes_sender.h"
#include "error_code_decoding.h"
#include "web_stats.h"
#include "esp_timer.h"
#include "webserver.hpp"

static const char *TAG_UWB = "UWB_DATA";

// HB TLV ID-k – ugyanazok, mint ble.c-ben
#define T_STATUS     0x01
#define T_UPTIME_MS  0x02
#define T_SYNC_MS    0x03

static uint8_t  g_last_hb_status = 0;
static uint32_t g_last_hb_uptime = 0;
static uint16_t g_last_hb_sync   = 0;

uint32_t uptime = 0;
uint32_t sync_ms = 0;

typedef struct {
    uint32_t rx_total;
    uint32_t tx_total;
    uint32_t err_total;
    // az utolsó /api/stats hívás óta bejött mennyiség:
    uint32_t rx_since_last;
    uint32_t err_since_last;
    uint64_t last_ts_ms;
} kpi_counter_t;

static kpi_counter_t g_ble_kpi;
static kpi_counter_t g_eth_kpi;

static void kpi_inc_rx(kpi_counter_t *k)
{
    uint64_t now_ms = esp_timer_get_time() / 1000ULL;

    if (k->last_ts_ms == 0) {
        k->last_ts_ms = now_ms;
    }

    k->rx_total++;
    k->rx_since_last++;
}

void ble_logger_on_ble_packet(void)
{
    kpi_inc_rx(&g_ble_kpi);
}

void ble_logger_on_eth_packet(void)
{
    kpi_inc_rx(&g_eth_kpi);
}

void ble_logger_get_kpi(ble_eth_kpi_t *ble, ble_eth_kpi_t *eth)
{
    uint64_t now_ms = esp_timer_get_time() / 1000ULL;

    if (ble) {
        uint64_t dt_ms = (g_ble_kpi.last_ts_ms > 0) ? (now_ms - g_ble_kpi.last_ts_ms) : 0;
        double   sec   = (dt_ms > 0) ? ((double)dt_ms / 1000.0) : 0.0;
        double   rx_r  = (sec > 0.0 && g_ble_kpi.rx_since_last > 0)
                         ? ((double)g_ble_kpi.rx_since_last / sec) : 0.0;
        double   err_r = (sec > 0.0 && g_ble_kpi.err_since_last > 0)
                         ? ((double)g_ble_kpi.err_since_last / sec) : 0.0;

        ble->rx_total = g_ble_kpi.rx_total;
        ble->tx_total = g_ble_kpi.tx_total;
        ble->err_total = g_ble_kpi.err_total;
        ble->rx_rate  = rx_r;
        ble->tx_rate  = 0.0;        // később bővíthető
        ble->err_rate = err_r;

        g_ble_kpi.rx_since_last  = 0;
        g_ble_kpi.err_since_last = 0;
        g_ble_kpi.last_ts_ms     = now_ms;
    }

    if (eth) {
        uint64_t dt_ms = (g_eth_kpi.last_ts_ms > 0) ? (now_ms - g_eth_kpi.last_ts_ms) : 0;
        double   sec   = (dt_ms > 0) ? ((double)dt_ms / 1000.0) : 0.0;
        double   rx_r  = (sec > 0.0 && g_eth_kpi.rx_since_last > 0)
                         ? ((double)g_eth_kpi.rx_since_last / sec) : 0.0;
        double   err_r = (sec > 0.0 && g_eth_kpi.err_since_last > 0)
                         ? ((double)g_eth_kpi.err_since_last / sec) : 0.0;

        eth->rx_total = g_eth_kpi.rx_total;
        eth->tx_total = g_eth_kpi.tx_total;
        eth->err_total = g_eth_kpi.err_total;
        eth->rx_rate  = rx_r;
        eth->tx_rate  = 0.0;
        eth->err_rate = err_r;

        g_eth_kpi.rx_since_last  = 0;
        g_eth_kpi.err_since_last = 0;
        g_eth_kpi.last_ts_ms     = now_ms;
    }
}

// forward deklaráció (prototípus)
void send_uwb_udp(const uint8_t *data, size_t len);

// FONTOS: NE legyen static, mert header-ben nem static a deklaráció
void uwb_notify_cb(const uint8_t *data, uint16_t len, bool from_cfg)
{
    /* ================= CFG TLV-k (HB) ================= */
    if (from_cfg) {
        if (len >= 3 && data[0] == T_STATUS && data[1] == 1) {
            uint8_t status = data[2];

            char msg[96];
            anchor_status_to_text(status, msg, sizeof(msg));
            printf("Anchor HB: status=0x%02X  %s\n", status, msg);

            const uint8_t *p   = data + 3;
            const uint8_t *end = data + len;
            uint32_t uptime = 0;
            uint16_t sync_ms = 0;

            while (p + 2 <= end) {
                uint8_t t = p[0];
                uint8_t l = p[1];
                p += 2;
                if (p + l > end) break;

                if (t == T_UPTIME_MS && l == 4) {
                    uptime = (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3];
                } else if (t == T_SYNC_MS && l == 2) {
                    sync_ms = (p[0]<<8)|p[1];
                }
                p += l;
            }

            g_last_hb_status = status;
            g_last_hb_uptime = uptime;
            g_last_hb_sync   = (uint16_t)sync_ms;

            ESP_LOGI("HB",
                     "HB status=%" PRIu8 " uptime=%" PRIu32 " ms sync_ms=%" PRIu32,
                     (uint8_t)status,
                     (uint32_t)uptime,
                     (uint32_t)sync_ms);

            /* --- Zóna azonosító beolvasása (ESP config / NVS) --- */
            uint16_t zone_id = esp_cfg_get_zone_id();

            char line[128];
            snprintf(line, sizeof(line),
                     "HB: HB status=%" PRIu8 " uptime=%" PRIu32 " ms sync_ms=%" PRIu32 " zone_id=0x%04X",
                     (uint8_t)status,
                     (uint32_t)uptime,
                     (uint32_t)sync_ms,
                     (unsigned)zone_id);

aes_sender_send_line(line);
            return;
        }
        return;
    }

    // Minden nem-CFG csomag: BLE KPI növelése
    ble_logger_on_ble_packet();

    /* ================= RÉGI 0xAB PREFIXES UWB PACKET ================= */
    if (len == sizeof(UWBPacket)) {
        UWBPacket pkt;
        memcpy(&pkt, data, sizeof(pkt));

        if (pkt.prefix != 0xAB) {
            ESP_LOGW(TAG_UWB, "prefix=0x%02X != 0xAB", pkt.prefix);
            return;
        }

        web_stats_log_tag(pkt.anchor_id, pkt.tag_id,
                          pkt.sync_seq, pkt.tag_seq,
                          pkt.batt_pct, pkt.timestamp);  // ÚJ

        ESP_LOGI(TAG_UWB,
                 "UWB: ver=%u sync=%u tag_seq=%u batt=%u%% anchor=0x%08" PRIX32
                 " tag=0x%08" PRIX32 " ts=%" PRIu64,
                 pkt.version, pkt.sync_seq, pkt.tag_seq,
                 pkt.batt_pct,
                 pkt.anchor_id, pkt.tag_id,
                 (uint64_t)pkt.timestamp);

        uint16_t zone_id = esp_cfg_get_zone_id();

        char line[200];
        snprintf(line, sizeof(line),
                 "UWB: ver=%u sync=%u tag_seq=%u batt=%u%% anchor=0x%08" PRIX32
                 " tag=0x%08" PRIX32 " ts=%" PRIu64 " zone_id=0x%04X",
                 pkt.version, pkt.sync_seq, pkt.tag_seq,
                 pkt.batt_pct,
                 pkt.anchor_id, pkt.tag_id,
                 (uint64_t)pkt.timestamp,
                 (unsigned)zone_id);
        aes_sender_send_line(line);
        return;
    }

    /* ================= Minden más: RAW továbbítás ================= */
    ESP_LOGW(TAG_UWB,
             "ISMERETLEN UWB packet, len=%u – RAW hex továbbítva",
             (unsigned)len);
    send_uwb_udp(data, len);

}

uint8_t  status_get_last_hb_status(void) { return g_last_hb_status; }
uint32_t status_get_last_hb_uptime(void) { return g_last_hb_uptime; }
uint16_t status_get_last_hb_sync_ms(void){ return g_last_hb_sync;  }

void send_uwb_udp(const uint8_t *data, size_t len)
{
    if (!data || len == 0) return;

    char tmp[512];
    if (len > 500) len = 500;

    for (int i = 0; i < len; i++)
        sprintf(tmp + i*3, "%02X ", data[i]);

    aes_sender_send_line(tmp);
}
