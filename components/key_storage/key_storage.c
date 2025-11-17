#include "key_storage.h"
#include "nvs_flash.h"
#include "nvs.h"
#include <string.h>

#define NVS_NS "secure"
#define NVS_KEY "aeskey"

bool key_storage_save(const char *hex32)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return false;

    esp_err_t er = nvs_set_str(h, NVS_KEY, hex32);
    if (er == ESP_OK) er = nvs_commit(h);

    nvs_close(h);
    return er == ESP_OK;
}

bool key_storage_load(char *out_hex32)
{
    nvs_handle_t h;
    size_t len = 64;

    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return false;

    esp_err_t er = nvs_get_str(h, NVS_KEY, out_hex32, &len);
    nvs_close(h);

    return er == ESP_OK;
}
