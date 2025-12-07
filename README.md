# ESP32_olimex_anchore

Firmware egy **UWB IPS anchor** eszközhöz, amely  
- egy **Ethernetes ESP32** (Olimex board) és  
- egy **UWB modul (DWM / UWB anchor)** között közvetít,  
- BLE-n keresztül konfigurálja a UWB modult,  
- titkosított (AES-CTR) UDP csomagokban továbbítja az IPS / TDoA adatokat a hálózati backend felé,  
- beépített **webes admin felülettel** rendelkezik (SPIFFS-en tárolt HTML/JS).

A projekt ESP-IDF 5.3.x-re épül (`sdkconfig`: ESP-IDF 5.3.1). :contentReference[oaicite:0]{index=0}  

---

## Fő funkciók

- **Ethernet inicializálás és IP beállítás**
  - DHCP vagy statikus IP, gateway, DNS kezelése. :contentReference[oaicite:1]{index=1}  
- **BLE kapcsolat a UWB modulhoz**
  - TLV-alapú konfiguráció BLE-n keresztül (network ID, zone ID, anchor ID, PHY, sync paraméterek). :contentReference[oaicite:2]{index=2}  
- **Konfigurálható IPS célok**
  - Több (max. 3) UDP cél IP/port, `ips_config_t` struktúrában. :contentReference[oaicite:3]{index=3}  
- **AES-CTR titkosítású UDP küldés**
  - AES kulcs NVS-ben tárolva (`key_storage` komponens), CTR módban titkosítás, broadcast/uni­cast UDP küldés. :contentReference[oaicite:4]{index=4} :contentReference[oaicite:5]{index=5}  
- **Webszerver + admin / super user UI**
  - HTTP szerver SPIFFS-es HTML/JS-t szolgál ki (admin panel, super user panel, statisztika). :contentReference[oaicite:6]{index=6} :contentReference[oaicite:7]{index=7}  
- **Részletes statisztika**
  - CPU/heap/flash/PSRAM kihasználtság, BLE/ETH forgalmi statok JSON-ben (`/api/stats`), frontenden grafikon/tabló. :contentReference[oaicite:8]{index=8} :contentReference[oaicite:9]{index=9}  

---

## Architektúra – áttekintés

Induláskor az `app_main()` a következő lépéseket hajtja végre: :contentReference[oaicite:10]{index=10}  

1. NVS inicializálás + szükség esetén törlés/újraformázás.
2. Globális konfiguráció betöltése (`globals_init()` – IP, IPS, státusz). :contentReference[oaicite:11]{index=11}  
3. ESP-IDF event loop és `esp_netif` inicializálása.
4. Ethernet driver konfigurálása (Olimex board PHY GPIO-k, link események). :contentReference[oaicite:12]{index=12}  
5. SPIFFS csatolása, webszerver indítása + stats modul. :contentReference[oaicite:13]{index=13}  
6. BLE konfiguráció betöltése NVS-ből (`web_ble_cfg_get()`), BLE név és UUID-ek beállítása, BLE scanner/cli indítása. :contentReference[oaicite:14]{index=14}  
7. UWB konfigurációs CLI inicializálása (`uwb_cfg_cli_init` – BLE TLV parancsok küldése a UWB modulnak). :contentReference[oaicite:15]{index=15}  

Adatfolyam röviden:

1. UWB modul BLE-n keresztül küldi a mért adatokat / állapotokat.
2. `ble.c` fogadja, `pretty_print.c` logolva/parszolva TLV formátumot. :contentReference[oaicite:16]{index=16}  
3. A mérési sorok / logok a `ble_logger`-en keresztül átkerülnek az `aes_sender` modulhoz. :contentReference[oaicite:17]{index=17} :contentReference[oaicite:18]{index=18}  
4. `aes_sender` AES-CTR-rel titkosítja az üzeneteket, majd `IPS.dest[]` alapján UDP-n kiküldi a megadott szerver(ek) felé. :contentReference[oaicite:19]{index=19}  

---

## Követelmények

- **Hardver**
  - ESP32 alapú Olimex Ethernet board (pl. ESP32-POE / ESP32-GATEWAY – a kód konkrétan Olimex PHY pin kiosztást használ). :contentReference[oaicite:20]{index=20}  
  - UWB anchor modul BLE kapcsolattal (a projekt UWB anchor gateway szerepet lát el).
- **Szoftver**
  - ESP-IDF 5.3.x (sdkconfig: 5.3.1) :contentReference[oaicite:21]{index=21}  
  - Python és ESP-IDF toolchain telepítve.

---

## Build és flash (ESP-IDF)

```bash
# ESP-IDF környezet betöltése
. $IDF_PATH/export.sh

# Céleszköz beállítása
idf.py set-target esp32

# Opcionális: konfiguráció
idf.py menuconfig

# Build
idf.py build

# Flash + monitor
idf.py -p /dev/ttyUSB0 flash monitor
