#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// AES-128 kulcs méret
#define AES_KEY_SIZE 16
#define AES_IV_SIZE  16

// Titkosított csomag maximális mérete
typedef struct {
    uint8_t iv[AES_IV_SIZE];
    uint8_t data[1024];
    size_t  len;
} encrypted_packet_t;

/**
 * AES rendszer inicializálása.
 *  - NVS-ből betölt egy "aes_key" kulcsot
 *  - ha nincs, létrehoz egy DEFAULT kulcsot
 */
void aes_sender_init(void);

/**
 * AES titkosítás CBC módban.
 * @param input      bemenet
 * @param input_len  bemenet mérete
 * @param out        ide kerül az IV + encrypted data
 * @return true      siker
 */
bool aes_encrypt_packet(const uint8_t *input, size_t input_len,
                        encrypted_packet_t *out);

/**
 * AES kulcs beállítása (webserverből hívva)
 */
bool aes_set_key(const uint8_t *new_key, size_t len);

/**
 * AES kulcs lekérdezése (debug/diagnosztika)
 */
bool aes_get_key(uint8_t *out_key);

#ifdef __cplusplus
}
#endif
