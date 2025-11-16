#pragma once
#include <stdint.h>
#include "lwip/ip_addr.h"

/* --- hálózati beállítások az ESP32-nek --- */
typedef struct {
    ip4_addr_t ip;
    ip4_addr_t gw;
    ip4_addr_t mask;
    ip4_addr_t dns1;
    ip4_addr_t dns2;
    uint16_t   udp_port;      // ha kell saját listen port (nem kötelező)
    uint8_t    use_dhcp;      // 0 = statikus, 1 = DHCP (később jól jöhet)
} net_config_t;

extern net_config_t NET;
extern volatile int eth_up;

/* --- IPS / TDoA kimeneti célok --- */
typedef struct {
    ip4_addr_t dest_ip;       // cél IP
    uint16_t   dest_port;     // cél port
    uint8_t    enabled;       // 0/1
} udp_dest_t;

typedef struct {
    uint32_t   gw_id;         // gateway / anchor azonosító
    uint32_t   hb_ms;         // heartbeat periódus
    udp_dest_t dest[3];       // max. 3 cél IP:PORT
} ips_config_t;

extern ips_config_t IPS;

/* --- státusz --- */
typedef enum { ST_UNKNOWN=0, ST_OK, ST_WARN, ST_ERR } state_t;

typedef struct {
    const char* anchor;   // "A1" stb.
    uint8_t     id;
    float       last_meas_s;
    float       last_volt;
    state_t     state;
} status_t;

extern status_t g_status;

void globals_init(void);
