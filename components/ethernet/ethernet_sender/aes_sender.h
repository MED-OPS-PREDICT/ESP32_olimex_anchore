#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef AES_IV_SIZE
#define AES_IV_SIZE 16
#endif

typedef struct {
    uint8_t iv[AES_IV_SIZE];
    uint8_t data[512];
    size_t  len;
} encrypted_packet_t;

bool aes_encrypt_packet(const uint8_t *in, size_t in_len, encrypted_packet_t *out);

void aes_sender_init(void);
void aes_sender_set_key_hex(const char *hex);
void aes_sender_send_line(const char *line);

#ifdef __cplusplus
}
#endif
