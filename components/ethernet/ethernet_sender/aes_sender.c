#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/ip_addr.h"

#include "mbedtls/aes.h"

#include "globals.h"      // IPS
#include "aes_sender.h"

#include "lwip/ip4_addr.h"

static const char *TAG = "AES_SENDER";

static int s_sock = -1;

static uint8_t s_key[16];
static bool    s_key_set = false;
static mbedtls_aes_context s_aes;

/* --------- segéd: UDP socket --------- */

static void ensure_socket(void)
{
    if (s_sock >= 0) {
        return;
    }

    s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (s_sock < 0) {
        ESP_LOGE(TAG, "socket() failed");
        return;
    }

    struct timeval tv = {
        .tv_sec  = 0,
        .tv_usec = 200000   // 200 ms send timeout
    };
    setsockopt(s_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* --------- segéd: AES-CTR titkosítás --------- */

static bool encrypt_ctr(const uint8_t *plaintext, size_t len,
                        uint8_t *out_buf, size_t out_buf_size,
                        size_t *out_len)
{
    /* out_buf = [16B IV][ciphertext...] */
    if (out_buf_size < len + 16) {
        return false;
    }

    uint8_t iv[16] = {0};

    /* IV első 8 byte: timestamp (us) big-endian */
    uint64_t now_us = (uint64_t)esp_timer_get_time();
    for (int i = 0; i < 8; ++i) {
        iv[7 - i] = (now_us >> (8 * i)) & 0xFF;
    }

    memcpy(out_buf, iv, 16);

    uint8_t stream_block[16];
    size_t nc_off = 0;

    int ret = mbedtls_aes_crypt_ctr(&s_aes,
                                    len,
                                    &nc_off,
                                    iv,
                                    stream_block,
                                    plaintext,
                                    out_buf + 16);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_aes_crypt_ctr ret=%d", ret);
        return false;
    }

    *out_len = len + 16;
    return true;
}

/* --------- publikus API --------- */

void aes_sender_init(void)
{
    ensure_socket();
    mbedtls_aes_init(&s_aes);
}

/* hex → 16 byte kulcs */
static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void aes_sender_set_key_hex(const char *hex32)
{
    if (!hex32) {
        return;
    }

    uint8_t key[16];

    for (int i = 0; i < 16; ++i) {
        int hi = hex_val(hex32[2*i]);
        int lo = hex_val(hex32[2*i+1]);
        if (hi < 0 || lo < 0) {
            ESP_LOGW(TAG, "invalid AES_KEY_HEX");
            return;
        }
        key[i] = (uint8_t)((hi << 4) | lo);
    }

    memcpy(s_key, key, 16);
    s_key_set = true;
    mbedtls_aes_setkey_enc(&s_aes, s_key, 128);
    ESP_LOGI(TAG, "AES key set");
    // opcionális: végén a "return;" el is hagyható
}

/* IPS.dest[0..2] -> 3 cél IP/port */
void aes_sender_send_line(const char *line)
{
    if (!s_key_set || !line || !line[0]) {
        return;
    }

    ensure_socket();
    if (s_sock < 0) {
        return;
    }

    size_t plain_len = strlen(line);
    if (plain_len > 512) {
        plain_len = 512;
    }

    uint8_t buf[16 + 512];
    size_t enc_len = 0;

    if (!encrypt_ctr((const uint8_t *)line, plain_len,
                     buf, sizeof(buf), &enc_len)) {
        return;
    }

    // DEBUG: plaintext + kimenő titkosított csomag kiírása
    ESP_LOGI(TAG, "PLAINTEXT len=%u: \"%.*s\"",
             (unsigned)plain_len, (int)plain_len, line);

    // ha van: esp_log_buffer_hex vagy esp_log_buffer_hexdump
    esp_log_buffer_hex(TAG, buf, enc_len);
    // vagy:
    // esp_log_buffer_hexdump(TAG, buf, enc_len, ESP_LOG_INFO);

    extern ips_config_t IPS;

    for (int i = 0; i < 3; ++i) {
        if (!IPS.dest[i].enabled) continue;
        if (IPS.dest[i].dest_port == 0) continue;
        if (IPS.dest[i].dest_ip.addr == 0) continue;

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family      = AF_INET;
        sa.sin_port        = htons(IPS.dest[i].dest_port);
        sa.sin_addr.s_addr = IPS.dest[i].dest_ip.addr;

        ESP_LOGI(TAG,
                 "sendto idx=%d %d.%d.%d.%d:%u len=%u",
                 i,
                 ip4_addr1_16(&IPS.dest[i].dest_ip),
                 ip4_addr2_16(&IPS.dest[i].dest_ip),
                 ip4_addr3_16(&IPS.dest[i].dest_ip),
                 ip4_addr4_16(&IPS.dest[i].dest_ip),
                 (unsigned)IPS.dest[i].dest_port,
                 (unsigned)enc_len);


        int sent = sendto(s_sock, buf, enc_len, 0,
                          (struct sockaddr *)&sa, sizeof(sa));
        if (sent < 0) {
            ESP_LOGW(TAG, "sendto idx=%d failed", i);
        }
    }
}
