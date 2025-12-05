#pragma once
#include "esp_err.h"

/* A header-t C és C++ alatt is elérhetővé tesszük */
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ROLE_NONE = 0,
    ROLE_DIAG = 1,
    ROLE_BLE  = 2,
    ROLE_ROOT = 3
} user_role_t;

esp_err_t webserver_start(void);
esp_err_t webserver_stop(void);

typedef struct {
    char     name[32];
    char     svc_uuid[40];
    char     data_uuid[40];
    char     cfg_uuid[40];
    uint16_t req_id;
} web_ble_cfg_t;

const web_ble_cfg_t* web_ble_cfg_get(void);

#ifdef __cplusplus
}
#endif
