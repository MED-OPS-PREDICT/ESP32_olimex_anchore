#include "globals.h"
#include "lwip/ip4_addr.h"

net_config_t NET;
ips_config_t IPS;
volatile int eth_up = 0;

void globals_init(void)
{
    /* --- saját hálózati beállítások --- */
    IP4_ADDR(&NET.ip,   192,168,0,191);
    IP4_ADDR(&NET.gw,   192,168,0,1);
    IP4_ADDR(&NET.mask, 255,255,255,0);
    IP4_ADDR(&NET.dns1, 1,1,1,1);
    IP4_ADDR(&NET.dns2, 8,8,8,8);
    NET.udp_port = 12345;      // ha kell saját listen port
    NET.use_dhcp = 0;          // most még fix IP

    /* --- IPS / UDP defaultok (ezeket fogod a webszerveren állítani) --- */
    IPS.gw_id = 1;             // pl. 1 vagy 0xA1
    IPS.hb_ms = 1000;          // 1 s heartbeat

    // Cél 1: egy tipikus szerver
    IP4_ADDR(&IPS.dest[0].dest_ip, 192,168,0,100);
    IPS.dest[0].dest_port = 60000;
    IPS.dest[0].enabled   = 1;

    // Cél 2,3 alapból kikapcsolva
    IP4_ADDR(&IPS.dest[1].dest_ip, 0,0,0,0);
    IPS.dest[1].dest_port = 0;
    IPS.dest[1].enabled   = 0;

    IP4_ADDR(&IPS.dest[2].dest_ip, 0,0,0,0);
    IPS.dest[2].dest_port = 0;
    IPS.dest[2].enabled   = 0;
}

status_t g_status = { "A1", 1, 0.0f, 0.0f, ST_UNKNOWN };
