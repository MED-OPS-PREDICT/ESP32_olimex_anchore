#pragma once
#include <stdbool.h>

bool key_storage_load(char *out_hex32);
bool key_storage_save(const char *hex32);
