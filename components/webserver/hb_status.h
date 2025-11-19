#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t  hb_get_status(void);
uint32_t hb_get_uptime_ms(void);
uint32_t hb_get_sync_ms(void);
bool     hb_has_status(void);

#ifdef __cplusplus
}
#endif
