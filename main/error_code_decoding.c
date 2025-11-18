#include "error_code_decoding.h"
#include <stdio.h>
#include <string.h>

const char *anchor_status_to_text(uint8_t st, char *buf, size_t buflen)
{
    bool has_ble   = (st & ST_BLE_LINK)    != 0;
    bool cfg_ntf   = (st & ST_CFG_NOTIFY)  != 0;
    bool prelock   = (st & ST_SYNC_PRELOCK)!= 0;
    bool lock      = (st & ST_SYNC_LOCK)   != 0;
    bool wd_reset  = (st & ST_RX_WD_RESET) != 0;
    bool rx_err    = (st & ST_RX_ERR_SEEN) != 0;

    if (!has_ble) {
        snprintf(buf, buflen, "Nincs BLE kapcsolat az anchorral");
        return buf;
    }

    if (!cfg_ntf) {
        snprintf(buf, buflen, "BLE OK, de HB/notify nincs engedélyezve");
        return buf;
    }

    if (!lock && !prelock) {
        snprintf(buf, buflen, "Nincs UWB SYNC (nem jönnek A/B keretek)");
        return buf;
    }

    if (lock && prelock) {
        snprintf(buf, buflen, "SYNC LOCK, de a szinkron régi (WARN)");
    } else if (lock) {
        snprintf(buf, buflen, "SYNC rendben (LOCK)");
    } else if (prelock) {
        snprintf(buf, buflen, "SYNC felépülőben (PRELOCK)");
    }

    if (wd_reset || rx_err) {
        size_t len = strnlen(buf, buflen);
        if (len < buflen - 4) {
            strncat(buf, " – ", buflen - len - 1);
        }
        if (wd_reset && rx_err) {
            strncat(buf, "watchdog reset és RX hibák voltak", buflen - strnlen(buf, buflen) - 1);
        } else if (wd_reset) {
            strncat(buf, "watchdog reset volt", buflen - strnlen(buf, buflen) - 1);
        } else if (rx_err) {
            strncat(buf, "RX hibák voltak", buflen - strnlen(buf, buflen) - 1);
        }
    }

    return buf;
}

const char *anchor_status_short(uint8_t st)
{
    bool has_ble   = st & ST_BLE_LINK;
    bool cfg_ntf   = st & ST_CFG_NOTIFY;
    bool prelock   = st & ST_SYNC_PRELOCK;
    bool lock      = st & ST_SYNC_LOCK;

    if (!has_ble)             return "NO BLE";
    if (!cfg_ntf)             return "NO HB";
    if (!lock && !prelock)    return "NO SYNC";
    if (lock && prelock)      return "SYNC WARN";
    if (lock)                 return "SYNC OK";
    if (prelock)              return "SYNC PRE";
    return "UNKNOWN";
}
