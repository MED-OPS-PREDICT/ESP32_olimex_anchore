#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/ip_addr.h"

#include "mbedtls/aes.h"

#include "globals.h"
#include "aes_sender.h"

#include "esp_netif.h"
#include "ble_logger.h"

static const char *TAG = "AES_SENDER";

static int s_sock = -1;

static uint8_t s_key[16];
static bool    s_key_set = false;
static mbedtls_aes_context s_aes;

/* ================= HEX -> BYTE ================= */

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ================= SOCKET ================= */

static void ensure_socket(void)
{
    if (s_sock >= 0) return;

    s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (s_sock < 0) {
        ESP_LOGE(TAG, "socket() failed");
        return;
    }

    int on = 1;
    setsockopt(s_sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));

    struct timeval tv = {
        .tv_sec  = 0,
        .tv_usec = 200000
    };
    setsockopt(s_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    ESP_LOGI(TAG, "UDP socket ready");
}

/* ================= AES-CTR ================= */

static bool encrypt_ctr(const uint8_t *plaintext, size_t len,
                        uint8_t *out_buf, size_t out_buf_size,
                        size_t *out_len)
{
    if (out_buf_size < len + 16) return false;

    uint8_t iv[16] = {0};

    uint64_t now_us = esp_timer_get_time();
    for (int i = 0; i < 8; ++i)
        iv[7 - i] = (now_us >> (8 * i)) & 0xFF;

    memcpy(out_buf, iv, 16);

    uint8_t stream_block[16];
    size_t nc_off = 0;

    int ret = mbedtls_aes_crypt_ctr(&s_aes, len, &nc_off,
                                    iv, stream_block,
                                    plaintext, out_buf + 16);

    if (ret != 0) {
        ESP_LOGE(TAG, "aes_ctr ret=%d", ret);
        return false;
    }

    *out_len = len + 16;
    return true;
}

/* ================= API ================= */

void aes_sender_init(void)
{
    ensure_socket();
    mbedtls_aes_init(&s_aes);
}

void aes_sender_set_key_hex(const char *hex32)
{
    if (!hex32) return;

    for (int i = 0; i < 16; ++i) {
        int hi = hex_val(hex32[2*i]);
        int lo = hex_val(hex32[2*i+1]);
        if (hi < 0 || lo < 0) {
            ESP_LOGW(TAG, "invalid AES key");
            return;
        }
        s_key[i] = (hi << 4) | lo;
    }

    mbedtls_aes_setkey_enc(&s_aes, s_key, 128);
    s_key_set = true;
    ESP_LOGI(TAG, "AES key loaded");
}

void aes_sender_send_line(const char *line)
{
    if (!line || !line[0]) {
        ESP_LOGW("AES_SENDER", "empty line, skip");
        return;
    }

    if (!s_key_set) {
        ESP_LOGE("AES_SENDER", "key not set, DROP");
        return;
    }

    ensure_socket();
    if (s_sock < 0) {
        ESP_LOGE("AES_SENDER", "no UDP socket");
        return;
    }

    size_t plain_len = strlen(line);
    if (plain_len > 500) plain_len = 500;

    uint8_t out[16 + 512];
    size_t enc_len = 0;

    bool ok = encrypt_ctr((const uint8_t*)line,
                          plain_len,
                          out,
                          sizeof(out),
                          &enc_len);
    if (!ok) {
        ESP_LOGE("AES_SENDER", "encrypt_ctr FAILED (plain_len=%u)", (unsigned)plain_len);
        return;
    }

    extern ips_config_t IPS;

    for (int i = 0; i < 3; i++) {
        if (!IPS.dest[i].enabled) continue;

        struct sockaddr_in sa = { 0 };
        sa.sin_family      = AF_INET;
        sa.sin_port        = htons(IPS.dest[i].dest_port);
        sa.sin_addr.s_addr = IPS.dest[i].dest_ip.addr;

        ble_logger_on_eth_packet();

        sendto(s_sock, out, enc_len, 0,
               (struct sockaddr*)&sa, sizeof(sa));
    }
}
