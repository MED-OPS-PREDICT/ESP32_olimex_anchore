// super_tooltips.js
// Minden tooltip szöveg egy helyen

window.SUPER_TOOLTIPS = {
  // fix mezők (header alatti inputok) – id alapján
  inputs: {
    svcUuid:  'BLE szolgáltatás UUID-je, amit az anchor hirdet.',
    cfgUuid:  'Konfigurációs karakterisztika UUID – ezen keresztül megy a CFG GET/SET.',
    dataUuid: 'Adat karakterisztika UUID – mérési / adat csatorna.',
    reqId:    'Kérések azonosítója (uint16). BEÁLLÍT és LEKÉR műveletekhez használja a firmware.'
  },

  // konfigurációs kulcsok – GROUPS.*.k szerint
  keys: {
    // base (ESP + DWM)
    NETWORK_ID: 'UWB hálózat azonosító. Csak az azonos NETWORK_ID-jű eszközök kommunikálnak.',
    ZONE_ID:    'Logikai zóna azonosító. Hex formában: pl. 0x0001.',
    ANCHOR_ID:  'Anchor egyedi azonosítója a zónán belül.',
    HB_MS:      'Anchor heartbeat periódus milliszekundumban.',
    LOG_LEVEL:  'Firmware logolási szintje (minél nagyobb, annál részletesebb).',
    TX_ANT_DLY: 'Adó antenna késleltetés (kalibrációs érték, tick egység).',
    RX_ANT_DLY: 'Vevő antenna késleltetés (kalibrációs érték, tick egység).',
    BIAS_TICKS: 'Bias korrekció ticks egységben (távolság-kompenzáció).',
    PHY_CH:     'Rádiócsatorna (UWB channel).',
    PHY_SFDTO:  'SFD timeout beállítás (időzítés, hibadetektálás).',

    // ips (ESP only)
    ZONE_NAME:   'Zóna emberi olvasású neve (pl. Raktár 1).',
    DEVICE_NAME: 'Eszköz neve, ami a felsőbb rendszerekben is megjelenik.',
    DEVICE_DESC: 'Rövid leírás / megjegyzés az eszközről.',
    ETH_MODE:    'Ethernet mód: 0 = DHCP, 1 = statikus IP.',
    ETH_IP:      'ESP statikus IP címe (ha ETH_MODE = 1).',
    ETH_MASK:    'Alhálózati maszk (pl. 255.255.255.0).',
    ETH_GW:      'Alapértelmezett gateway IP címe.',
    GW_ID:       'Gateway azonosító (felsőbb rendszerhez).',
    AES_KEY:     'AES kulcs 32 byte hex formában (64 hex karakter).',

    ZONE_CTRL_IP:   'Zóna vezérlő IP címe.',
    ZONE_CTRL_PORT: 'Zóna vezérlő TCP/UDP portja.',
    ZONE_CTRL_EN:   'Zóna vezérlő engedélyezése (0 = tiltva, 1 = engedélyezve).',

    MAIN_IP:    'Fő szerver IP címe.',
    MAIN_PORT:  'Fő szerver TCP/UDP portja.',
    MAIN_EN:    'Fő szerver engedélyezése (0 = tiltva, 1 = engedélyezve).',

    SERVICE_IP:   'Service / karbantartó szolgáltatás IP címe.',
    SERVICE_PORT: 'Service port.',
    SERVICE_EN:   'Service engedélyezése (0 = tiltva, 1 = engedélyezve).',

    // sync (DWM)
    PPM_MAX:     'Megengedett maximális óraeltérés (ppm).',
    JUMP_PPM:    'Nagyobb óraugrás detektálási küszöb (ppm).',
    AB_GAP_MS:   'A/B anchor közötti időrés (ms).',
    MS_EWMA_DEN: 'Master-slave szinkron EWMA szűrő nevező.',
    TK_EWMA_DEN: 'Timekeeping EWMA szűrő nevező.',
    TK_MIN_MS:   'Időbélyeg frissítés minimális periódusa (ms).',
    TK_MAX_MS:   'Időbélyeg frissítés maximális periódusa (ms).',
    DTTX_MIN_MS: 'Minimális TX időköz (ms).',
    DTTX_MAX_MS: 'Maximális TX időköz (ms).',
    LOCK_NEED:   'Szinkron “lock” eléréséhez szükséges jó minták száma.',

    // phy (DWM)
    PHY_PLEN:     'Preamble hossz (sym).',
    PHY_PAC:      'PAC méret (preamble acquisition chunk).',
    PHY_TX_CODE:  'TX preamble kód.',
    PHY_RX_CODE:  'RX preamble kód.',
    PHY_SFD:      'SFD mód / minta.',
    PHY_BR:       'Adatsebesség (bitrate).',
    PHY_PHRMODE:  'PHR mód (frame header).',
    PHY_PHRRATE:  'PHR bitsebesség.',
    PHY_STS_MODE: 'STS (Secure Time Stamp) mód.',
    PHY_STS_LEN:  'STS hossz.',
    PHY_PDOA:     'PDOA konfiguráció (irány meghatározás).'
  }
};
