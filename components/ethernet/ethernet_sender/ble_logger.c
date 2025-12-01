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

            char line[128];
            snprintf(line, sizeof(line),
                     "HB: HB status=%" PRIu8 " uptime=%" PRIu32 " ms sync_ms=%" PRIu32,
                     (uint8_t)status,
                     (uint32_t)uptime,
                     (uint32_t)sync_ms);
            aes_sender_send_line(line);
            return;
        }
        return;
    }

    /* ================= RÉGI 0xAB PREFIXES UWB PACKET ================= */
    if (len == sizeof(UWBPacket)) {
        UWBPacket pkt;
        memcpy(&pkt, data, sizeof(pkt));

        if (pkt.prefix != 0xAB) {
            ESP_LOGW(TAG_UWB, "prefix=0x%02X != 0xAB", pkt.prefix);
            return;
        }

        ESP_LOGI(TAG_UWB,
                 "UWB: ver=%u sync=%u tag_seq=%u batt=%u%% anchor=0x%08" PRIX32
                 " tag=0x%08" PRIX32 " ts=%" PRIu64,
                 pkt.version, pkt.sync_seq, pkt.tag_seq,
                 pkt.batt_pct,
                 pkt.anchor_id, pkt.tag_id,
                 (uint64_t)pkt.timestamp);

        char line[200];
        snprintf(line, sizeof(line),
                 "UWB: ver=%u sync=%u tag_seq=%u batt=%u%% anchor=0x%08" PRIX32
                 " tag=0x%08" PRIX32 " ts=%" PRIu64,
                 pkt.version, pkt.sync_seq, pkt.tag_seq,
                 pkt.batt_pct,
                 pkt.anchor_id, pkt.tag_id,
                 (uint64_t)pkt.timestamp);
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
