#pragma once
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool key_storage_load(char *out_hex32);
bool key_storage_save(const char *hex32);

#ifdef __cplusplus
}
#endif
