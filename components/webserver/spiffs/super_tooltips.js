// /spiffs/super_tooltips.js
// NINCS <script> TAG, CSAK JS!

window.SUPER_TOOLTIPS = {
  keys: {
    NETWORK_ID: "UWB hálózati azonosító. Minden anchoron azonos legyen.",
    ZONE_ID:    "Zóna azonosító (hex, pl. 0x1234). Ugyanaz a zónában lévő anchornál.",
    ANCHOR_ID:  "Anchor egyedi azonosító (32 bites hex).",
    HB_MS:      "Heartbeat periódus ezredmásodpercben.",
    LOG_LEVEL:  "Logolási szint (0..n).",
    TX_ANT_DLY: "Adó antenna késleltetés (tick / ps), kalibrációs érték.",
    RX_ANT_DLY: "Vevő antenna késleltetés (tick / ps), kalibrációs érték.",
    BIAS_TICKS: "Mérési bias kompenzáció (tick).",
    PHY_CH:     "UWB csatorna (pl. 5, 9).",
    PHY_SFDTO:  "SFD timeout (sym).",

    // IPS csoport
    ZONE_NAME:   "Zóna megnevezése (UI-ban jelenik meg).",
    DEVICE_NAME: "Eszköz neve (pl. ANCHOR_01).",
    DEVICE_DESC: "Rövid leírás, helyszín, megjegyzés.",

    ETH_MODE: "0 = DHCP, 1 = statikus IP.",
    ETH_IP:   "Saját IP cím.",
    ETH_MASK: "Hálózati maszk.",
    ETH_GW:   "Alapértelmezett gateway.",

    GW_ID: "Gateway ID, IPS konfigurációból.",

    AES_KEY: "AES titkosító kulcs hex formában (32 byte = 64 hex karakter).",

    ZONE_CTRL_IP:   "Zóna vezérlő IP címe.",
    ZONE_CTRL_PORT: "Zóna vezérlő UDP/TCP port.",
    ZONE_CTRL_EN:   "Zóna vezérlő engedélyezése (0/1).",

    MAIN_IP:   "Fő szerver IP címe.",
    MAIN_PORT: "Fő szerver port.",
    MAIN_EN:   "Fő szerver engedélyezése (0/1).",

    SERVICE_IP:   "Service / menedzsment szerver IP.",
    SERVICE_PORT: "Service szerver port.",
    SERVICE_EN:   "Service szerver engedélyezése (0/1).",

    // sync
    PPM_MAX:     "Maximális frekvenciaeltérés ppm-ben.",
    JUMP_PPM:    "Ugrásérzékelés küszöb ppm-ben.",
    AB_GAP_MS:   "A-B szinkron ablak ms-ben.",
    MS_EWMA_DEN: "Mester-szolga szűrés EWMA nevező.",
    TK_EWMA_DEN: "Time-keeping szűrés EWMA nevező.",
    TK_MIN_MS:   "Időkövetés minimális periódus (ms).",
    TK_MAX_MS:   "Időkövetés maximális periódus (ms).",
    DTTX_MIN_MS: "TX időköz minimum (ms).",
    DTTX_MAX_MS: "TX időköz maximum (ms).",
    LOCK_NEED:   "Lockhoz szükséges csomagszám / feltétel.",

    // PHY
    PHY_PLEN:     "Preamble hossz.",
    PHY_PAC:      "PAC érték.",
    PHY_TX_CODE:  "TX kód index.",
    PHY_RX_CODE:  "RX kód index.",
    PHY_SFD:      "SFD beállítás.",
    PHY_BR:       "Bitráta.",
    PHY_PHRMODE:  "PHR mód.",
    PHY_PHRRATE:  "PHR bitráta.",
    PHY_STS_MODE: "STS mód.",
    PHY_STS_LEN:  "STS hossz.",
    PHY_PDOA:     "PDOA mód."
  },

  // fix input mezők ID alapján
  inputs: {
    svcUuid:   "BLE szolgáltatás UUID (GATT service).",
    cfgUuid:   "Konfigurációs karakterisztika UUID.",
    dataUuid:  "Adat karakterisztika UUID.",
    reqId:     "Kérés azonosító (tetszőleges, a válaszban visszajön)."
  }
};
