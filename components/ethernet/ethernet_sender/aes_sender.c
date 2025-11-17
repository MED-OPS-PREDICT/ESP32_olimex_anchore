#include "aes_sender.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/aes.h"
#include "esp_random.h"
#include <string.h>

static const char *TAG = "AES_SENDER";

static uint8_t aes_key[AES_KEY_SIZE];

// Belső: kulcs betöltése NVS-ből
static void load_key_from_nvs(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("sec", NVS_READONLY, &nvs);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "NVS no-key, using default test key.");
        memset(aes_key, 0x11, AES_KEY_SIZE); // DEFAULT kulcs
        return;
    }

    size_t size = AES_KEY_SIZE;
    err = nvs_get_blob(nvs, "aes_key", aes_key, &size);
    nvs_close(nvs);

    if (err == ESP_OK && size == AES_KEY_SIZE) {
        ESP_LOGI(TAG, "AES key loaded from NVS.");
    } else {
        ESP_LOGW(TAG, "No valid AES key, using default.");
        memset(aes_key, 0x11, AES_KEY_SIZE); // DEFAULT kulcs
    }
}

void aes_sender_init(void)
{
    load_key_from_nvs();
}

bool aes_set_key(const uint8_t *new_key, size_t len)
{
    if (len != AES_KEY_SIZE) return false;

    memcpy(aes_key, new_key, AES_KEY_SIZE);

    nvs_handle_t nvs;
    ESP_ERROR_CHECK(nvs_open("sec", NVS_READWRITE, &nvs));
    ESP_ERROR_CHECK(nvs_set_blob(nvs, "aes_key", new_key, AES_KEY_SIZE));
    ESP_ERROR_CHECK(nvs_commit(nvs));
    nvs_close(nvs);

    ESP_LOGI(TAG, "AES key stored in NVS.");
    return true;
}

bool aes_get_key(uint8_t *out_key)
{
    memcpy(out_key, aes_key, AES_KEY_SIZE);
    return true;
}

bool aes_encrypt_packet(const uint8_t *input, size_t input_len,
                        encrypted_packet_t *out)
{
    if (!input || !out) return false;

    // IV generálása
    for (int i = 0; i < AES_IV_SIZE; i++)
        out->iv[i] = esp_random() & 0xFF;

    // AES init
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, aes_key, AES_KEY_SIZE * 8);

    // Padding (PKCS#7)
    size_t pad = AES_KEY_SIZE - (input_len % AES_KEY_SIZE);
    size_t enc_len = input_len + pad;

    uint8_t buffer[1024];
    if (enc_len > sizeof(buffer))
        return false;

    memcpy(buffer, input, input_len);
    memset(buffer + input_len, pad, pad);

    uint8_t iv_copy[AES_IV_SIZE];
    memcpy(iv_copy, out->iv, AES_IV_SIZE);

    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT,
                          enc_len, iv_copy, buffer, out->data);

    out->len = enc_len;

    mbedtls_aes_free(&aes);
    return true;
}
