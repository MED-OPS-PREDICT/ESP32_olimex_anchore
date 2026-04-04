#pragma once
#include <stdbool.h>
#include "esp_netif.h"
#include "esp_eth.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    esp_netif_t      *netif;
    esp_eth_handle_t  handle;
} ethernet_ctx_t;

/** Inicializálja az Ethernetet és visszaadja a kontextust. */
esp_err_t ethernet_init(ethernet_ctx_t *ctx);

/** Leállít és felszabadít. Opcionális. */
void ethernet_deinit(ethernet_ctx_t *ctx);

void ethernet_reapply_ip_from_net(void);

bool ethernet_is_link_up(void);
bool ethernet_has_ip(void);

#ifdef __cplusplus
}
#endif
