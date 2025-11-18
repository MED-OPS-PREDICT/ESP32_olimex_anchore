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

static const char *TAG_UWB = "UWB_DATA";

// HB TLV ID-k – ugyanazok, mint ble.c-ben
#define T_STATUS     0x01
#define T_UPTIME_MS  0x02
#define T_SYNC_MS    0x03

static uint8_t  g_last_hb_status = 0;
static uint32_t g_last_hb_uptime = 0;
static uint16_t g_last_hb_sync   = 0;

// FONTOS: NE legyen static, mert header-ben nem static a deklaráció
void uwb_notify_cb(const uint8_t *data, uint16_t len, bool from_cfg)
{
    // CFG notify most nem érdekel, csak DATA
    if (from_cfg) {
        // életjel/állapot TLV-k
        if (len >= 3 && data[0] == T_STATUS && data[1] == 1) {
            uint8_t status = data[2];

            char msg[96];
            anchor_status_to_text(status, msg, sizeof(msg));

            printf("Anchor HB: status=0x%02X  %s\n", status, msg);

            // keresd meg benne az UPTIME_MS és SYNC_MS TLV-ket
            const uint8_t *p = data + 3;
            const uint8_t *end = data + len;
            uint32_t uptime = 0;
            uint16_t sync_ms = 0;

            while (p + 2 <= end) {
                uint8_t t = p[0], l = p[1];
                p += 2;
                if (p + l > end) break;

                if (t == T_UPTIME_MS && l == 4) {
                    uptime = (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3];
                } else if (t == T_SYNC_MS && l == 2) {
                    sync_ms = (p[0]<<8)|p[1];
                }
                p += l;
            }

            ESP_LOGI("HB", "HB status=%u uptime=%u ms sync_ms=%u",
                     (unsigned)status,
                     (unsigned)uptime,
                     (unsigned)sync_ms);
            char line[128];
            snprintf(line, sizeof(line),
                     "HB status=%u uptime=%u ms sync_ms=%u",
                     (unsigned)status,
                     (unsigned)uptime,
                     (unsigned)sync_ms);
            aes_sender_send_line(line);
            return;
        }

        // egyéb CFG keretek (GET/SET/STATE) – ha kell, külön logold
        return;
    }

    if (len != sizeof(UWBPacket)) {
        ESP_LOGW(TAG_UWB, "DATA len=%u (var=%u), ignorálom",
                 (unsigned)len, (unsigned)sizeof(UWBPacket));
        return;
    }

    UWBPacket pkt;
    memcpy(&pkt, data, sizeof(pkt));

    if (pkt.prefix != 0xAB) {
        ESP_LOGW(TAG_UWB, "prefix=0x%02X != 0xAB", pkt.prefix);
        return;
    }

    // Szép, soros logra való egy sor
    ESP_LOGI(TAG_UWB,
             "ver=%u sync=%u tag_seq=%u anchor=0x%08" PRIX32
             " tag=0x%08" PRIX32 " ts=%" PRIu64,
             pkt.version,
             pkt.sync_seq,
             pkt.tag_seq,
             pkt.anchor_id,
             pkt.tag_id,
             (uint64_t)pkt.timestamp);
    char line[160];
    snprintf(line, sizeof(line),
             "ver=%u sync=%u tag_seq=%u anchor=0x%08" PRIX32
             " tag=0x%08" PRIX32 " ts=%" PRIu64,
             pkt.version,
             pkt.sync_seq,
             pkt.tag_seq,
             pkt.anchor_id,
             pkt.tag_id,
             (uint64_t)pkt.timestamp);
    aes_sender_send_line(line);
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
