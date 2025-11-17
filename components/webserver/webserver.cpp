// components/webserver/webserver.cpp
// HTTP szerver + auth + /api/status + /api/config
// A BLE TLV GET route-ot a http_server.c adja (http_register_routes)

#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cctype>          // isxdigit, tolower

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "mbedtls/base64.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "aes_sender.h"

#ifndef IPSTR
#define IPSTR "%d.%d.%d.%d"
#endif

#ifndef IP2STR
#define IP2STR(ipaddr) \
    ip4_addr1_16(ipaddr), \
    ip4_addr2_16(ipaddr), \
    ip4_addr3_16(ipaddr), \
    ip4_addr4_16(ipaddr)
#endif

#include "webserver.hpp"
#include "globals.h"   // g_status, stb.

extern "C" void ble_http_bridge_init(void);
extern "C" void http_register_routes(httpd_handle_t h);

static const char* TAG = "WEB";

/* ================= HTTPD handle ================= */
static httpd_handle_t s_http = nullptr;

/* ================= Users + Sessions ================= */
struct User { const char* u; const char* p; user_role_t r; };
static const User kUsers[] = {
    {"diag","diag",ROLE_DIAG},
    {"admin","admin",ROLE_BLE},
    {"root","root",ROLE_ROOT},
    {nullptr,nullptr,ROLE_NONE}
};
struct Session { char sid[33]; user_role_t role; uint32_t exp_s; };
static Session g_sess[8];

static void mk_sid(char out[33]){
    for(int i=0;i<32;i++){ uint8_t b = esp_random() & 0x0F; out[i] = "0123456789abcdef"[b]; }
    out[32] = 0;
}
static user_role_t check_user(const char* u, const char* pw){
    for (const auto& x: kUsers) if (x.u && strcmp(u,x.u)==0 && strcmp(pw,x.p)==0) return x.r;
    return ROLE_NONE;
}

/* ---------- Basic Auth decode ---------- */
static bool decode_basic(const char* h, std::string& u, std::string& p){
    if (!h) return false;
    const char* pref = "Basic ";
    if (strncmp(h, pref, 6) != 0) return false;
    const char* b64 = h + 6;
    size_t olen=0;
    (void)mbedtls_base64_decode(nullptr,0,&olen,(const unsigned char*)b64,strlen(b64));
    std::vector<unsigned char> buf(olen+1);
    if (mbedtls_base64_decode(buf.data(),olen,&olen,(const unsigned char*)b64,strlen(b64))!=0) return false;
    buf[olen]=0;
    char* sep = (char*)strchr((char*)buf.data(),':'); if(!sep) return false;
    *sep=0; u.assign((char*)buf.data()); p.assign(sep+1); return true;
}
static bool decode_basic_hdr(httpd_req_t* req, std::string& u, std::string& p){
    size_t len=httpd_req_get_hdr_value_len(req,"Authorization"); if(!len) return false;
    std::vector<char> auth(len+1);
    if(httpd_req_get_hdr_value_str(req,"Authorization",auth.data(),auth.size())!=ESP_OK) return false;
    return decode_basic(auth.data(), u, p);
}

/* ---------- Cookie (SID) ellenőrzés ---------- */
static user_role_t role_from_cookie(httpd_req_t* req){
    size_t n=httpd_req_get_hdr_value_len(req,"Cookie"); if(!n) return ROLE_NONE;
    std::vector<char> ck(n+1);
    if(httpd_req_get_hdr_value_str(req,"Cookie",ck.data(),ck.size())!=ESP_OK) return ROLE_NONE;
    const char* m=strstr(ck.data(),"SID="); if(!m) return ROLE_NONE; m+=4;
    char sid[33]={0}; int i=0; while(*m && *m!=';' && i<32) sid[i++]=*m++;
    uint32_t now=(uint32_t)(esp_timer_get_time()/1000000ULL);
    for(auto& s: g_sess) if(s.sid[0] && strcmp(s.sid,sid)==0 && s.exp_s>now) return s.role;
    return ROLE_NONE;
}
static user_role_t role_from_auth(httpd_req_t* req){
    user_role_t r = role_from_cookie(req);
    if (r != ROLE_NONE) return r;
    std::string u,p; if(!decode_basic_hdr(req,u,p)) return ROLE_NONE;
    return check_user(u.c_str(), p.c_str());
}
static bool require_role(httpd_req_t* req, user_role_t need){
    user_role_t r=role_from_auth(req);
    if(r<need){
        if (strncmp(req->uri,"/api/",5)==0 || strncmp(req->uri,"/auth/",6)==0){
            httpd_resp_set_status(req,"401 Unauthorized"); httpd_resp_sendstr(req,"");
        } else {
            httpd_resp_set_status(req,"302 Found"); httpd_resp_set_hdr(req,"Location","/login"); httpd_resp_sendstr(req,"");
        }
        return false;
    }
    return true;
}

/* ================= CORS + cache control ================= */
static void add_cors(httpd_req_t* r){
    httpd_resp_set_hdr(r, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(r, "Access-Control-Allow-Headers", "content-type, authorization");
    httpd_resp_set_hdr(r, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
}
static void add_no_cache(httpd_req_t* r){
    httpd_resp_set_hdr(r, "Cache-Control", "no-store, no-cache, must-revalidate");
    httpd_resp_set_hdr(r, "Pragma", "no-cache");
    httpd_resp_set_hdr(r, "Expires", "0");
}
static esp_err_t options_ok(httpd_req_t* req){
    add_cors(req);
    httpd_resp_set_status(req, "204 No Content");
    return httpd_resp_sendstr(req, "");
}

/* ================= Static file helper ================= */
static esp_err_t send_file(httpd_req_t* req, const char* path, const char* ctype){
    FILE* f=fopen(path,"rb");
    if(!f){ httpd_resp_send_err(req,HTTPD_404_NOT_FOUND,"Not found"); return ESP_FAIL; }
    httpd_resp_set_type(req, ctype);
    char buf[1024]; size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0){
        if(httpd_resp_send_chunk(req,buf,n)!=ESP_OK){ fclose(f); httpd_resp_sendstr_chunk(req,nullptr); return ESP_FAIL; }
    }
    fclose(f); httpd_resp_sendstr_chunk(req,nullptr); return ESP_OK;
}

/* ================= Pages ================= */
static esp_err_t login_get(httpd_req_t* r){ return send_file(r,"/spiffs/login.html","text/html"); }
static esp_err_t diag_get (httpd_req_t* r){ if(!require_role(r,ROLE_DIAG))return ESP_FAIL; return send_file(r,"/spiffs/diag.html","text/html"); }
static esp_err_t ble_get  (httpd_req_t* r){ if(!require_role(r,ROLE_BLE ))return ESP_FAIL; return send_file(r,"/spiffs/ble.html","text/html"); }
static esp_err_t admin_get(httpd_req_t* r){ if(!require_role(r,ROLE_ROOT))return ESP_FAIL; return send_file(r,"/spiffs/admin.html","text/html"); }
static esp_err_t super_user_get(httpd_req_t* r){ if(!require_role(r,ROLE_BLE))return ESP_FAIL; return send_file(r,"/spiffs/super_user.html","text/html"); }

/* ================= /auth/login ================= */
static esp_err_t auth_login_post(httpd_req_t* req){
    add_cors(req);
    add_no_cache(req);

    int len = req->content_len;
    if (len <= 0) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty");

    std::vector<char> body(len + 1, 0);
    int off = 0;
    while (off < len) {
        int r = httpd_req_recv(req, body.data() + off, len - off);
        if (r <= 0) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "recv");
        off += r;
    }
    ESP_LOGI(TAG, "login body: %s", body.data());

    char ctype[64] = {0};
    if (httpd_req_get_hdr_value_str(req, "Content-Type", ctype, sizeof(ctype)) != ESP_OK) ctype[0]=0;

    auto trim = [](std::string s) -> std::string {
        size_t a = s.find_first_not_of(" \t\r\n\"");
        size_t b = s.find_last_not_of(" \t\r\n\"");
        if (a == std::string::npos) {
            return std::string();
        }
        return s.substr(a, b - a + 1);
    };

    std::string user, pass;

    auto find_json = [&](const char* key)->std::string{
        const char* k = strstr(body.data(), key); if (!k) return {};
        k = strchr(k, ':'); if (!k) return {}; ++k;
        const char* p = k; while (*p==' '||*p=='\t'||*p=='\"') ++p;
        const char* q = p; while (*q && *q!='\"' && *q!=',' && *q!='}') ++q;
        return std::string(p, q - p);
    };

    auto url_decode = [](const char* s)->std::string{
        std::string out;
        for (; *s; ++s){
            if (*s == '+') out.push_back(' ');
            else if (*s == '%' && isxdigit((unsigned char)s[1]) && isxdigit((unsigned char)s[2])) {
                int hi = isdigit((unsigned char)s[1]) ? s[1]-'0' : 10 + (tolower((unsigned char)s[1])-'a');
                int lo = isdigit((unsigned char)s[2]) ? s[2]-'0' : 10 + (tolower((unsigned char)s[2])-'a');
                out.push_back((char)((hi<<4)|lo)); s+=2;
            } else out.push_back(*s);
        }
        return out;
    };
    auto get_form = [&](const char* key)->std::string{
        std::string k = std::string(key) + "=";
        const char* p = strstr(body.data(), k.c_str()); if (!p) return {};
        p += k.size(); const char* q = p; while (*q && *q != '&') ++q;
        return url_decode(std::string(p, q - p).c_str());
    };

    std::string cts(ctype);
    for (auto& ch : cts) ch = (char)tolower((unsigned char)ch);

    if (cts.find("application/json") != std::string::npos || strchr(body.data(), '{')) {
        user = trim(find_json("\"user\""));
        pass = trim(find_json("\"pass\""));
    } else {
        user = trim(get_form("user"));
        pass = trim(get_form("pass"));
    }

    if (user.empty() || pass.empty()) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad format");

    user_role_t r = check_user(user.c_str(), pass.c_str());
    if (r == ROLE_NONE) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "bad creds");

    char sid[33]; mk_sid(sid);
    uint32_t now = (uint32_t)(esp_timer_get_time()/1000000ULL);
    int idx = -1;
    for (int i = 0; i < (int)(sizeof(g_sess)/sizeof(g_sess[0])); ++i) if (g_sess[i].sid[0]==0){ idx=i; break; }
    if (idx < 0) idx = 0;

    memset(&g_sess[idx], 0, sizeof(g_sess[0]));
    strncpy(g_sess[idx].sid, sid, sizeof(g_sess[0].sid)-1);
    g_sess[idx].role = r;
    g_sess[idx].exp_s = now + 86400;

    std::string cookie = std::string("SID=")+sid+"; Path=/; HttpOnly; Max-Age=86400";
    httpd_resp_set_hdr(req, "Set-Cookie", cookie.c_str());
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}\n");
}

/* ================= ESP config tükör az UI-hoz ================= */
struct EspCfg {
    uint16_t NETWORK_ID = 1;
    uint16_t ZONE_ID    = 0x5A31;
    uint32_t ANCHOR_ID  = 0x00000001;
    uint16_t HB_MS      = 10000;
    uint8_t  LOG_LEVEL  = 1;
    int32_t  TX_ANT_DLY = 0;
    int32_t  RX_ANT_DLY = 0;
    int32_t  BIAS_TICKS = 0;
    uint8_t  PHY_CH     = 9;
    uint16_t PHY_SFDTO  = 248;

    /* --- ÚJ: gateway + 3 cél IP-csoport --- */
    uint32_t GW_ID      = 1;

    char ZONE_CTRL_IP[16] = "0.0.0.0";
    uint16_t ZONE_CTRL_PORT = 0;
    uint8_t  ZONE_CTRL_EN   = 0;

    char MAIN_IP[16] = "0.0.0.0";
    uint16_t MAIN_PORT = 0;
    uint8_t  MAIN_EN   = 0;

    char SERVICE_IP[16] = "0.0.0.0";
    uint16_t SERVICE_PORT = 0;
    uint8_t  SERVICE_EN   = 0;

    char AES_KEY_HEX[33] = "";   // 32 hex + '\0'

    // Saját ethernet:
    uint8_t  ETH_MODE = 0;         // 0 = DHCP, 1 = statikus
    char     ETH_IP[16]   = "0.0.0.0";
    char     ETH_MASK[16] = "0.0.0.0";
    char     ETH_GW[16]   = "0.0.0.0";

} g_cfg;

/* ==== NVS kezelés az ESP confighoz (g_cfg) ==== */

static const char* NVS_NS  = "cfg";
static const char* NVS_KEY = "esp_cfg";

static bool s_nvs_inited = false;

static void ensure_nvs_init(void)
{
    if (s_nvs_inited) return;

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err == ESP_OK) {
        s_nvs_inited = true;
        ESP_LOGI(TAG, "NVS init ok");
    } else {
        ESP_LOGW(TAG, "NVS init failed: 0x%x", err);
    }
}

/* NVS -> g_cfg. true, ha sikerült valamit betölteni */
static bool esp_cfg_load_from_nvs(void)
{
    ensure_nvs_init();
    if (!s_nvs_inited) return false;

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "no cfg in NVS (open err=0x%x), using defaults", err);
        return false;
    }

    size_t sz = 0;
    err = nvs_get_blob(h, NVS_KEY, NULL, &sz);
    if (err != ESP_OK || sz == 0 || sz > sizeof(EspCfg)) {
        ESP_LOGW(TAG, "no/invalid blob (err=0x%x, sz=%u), using defaults",
                 err, (unsigned)sz);
        nvs_close(h);
        return false;
    }

    /* induljunk a fordításkori defaultokból,
       és csak a blob hosszáig írjuk felül */
    EspCfg tmp = g_cfg;
    err = nvs_get_blob(h, NVS_KEY, &tmp, &sz);
    nvs_close(h);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_get_blob err=0x%x, using defaults", err);
        return false;
    }

    g_cfg = tmp;
    ESP_LOGI(TAG, "EspCfg loaded from NVS (size=%u)", (unsigned)sz);
    return true;
}

/* g_cfg -> NVS */
static void esp_cfg_save_to_nvs(void)
{
    ensure_nvs_init();
    if (!s_nvs_inited) return;

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_open write err=0x%x", err);
        return;
    }

    err = nvs_set_blob(h, NVS_KEY, &g_cfg, sizeof(g_cfg));
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_set_blob err=0x%x", err);
        nvs_close(h);
        return;
    }

    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "EspCfg saved to NVS (size=%u)", (unsigned)sizeof(g_cfg));
}

static bool find_key(const char* body, const char* key, const char** val_start){
    const char* p=strstr(body,key); if(!p) return false;
    p=strchr(p,':'); if(!p) return false; p++;
    while(*p==' '||*p=='\"'){ if(*p=='\"'){ *val_start=p; return true; } ++p; }
    *val_start=p; return true;
}

static void json_cfg_print(char* buf, size_t sz, const EspCfg& c){
    snprintf(buf, sz,
      "{"
      "\"NETWORK_ID\":%u,"
      "\"ZONE_ID\":\"0x%04X\","
      "\"ANCHOR_ID\":\"0x%08X\","
      "\"HB_MS\":%u,"
      "\"LOG_LEVEL\":%u,"
      "\"TX_ANT_DLY\":%d,"
      "\"RX_ANT_DLY\":%d,"
      "\"BIAS_TICKS\":%d,"
      "\"PHY_CH\":%u,"
      "\"PHY_SFDTO\":%u,"

      "\"GW_ID\":%u,"

      "\"ETH_MODE\":%u,"
      "\"ETH_IP\":\"%s\","
      "\"ETH_MASK\":\"%s\","
      "\"ETH_GW\":\"%s\","

      "\"ZONE_CTRL_IP\":\"%s\","
      "\"ZONE_CTRL_PORT\":%u,"
      "\"ZONE_CTRL_EN\":%u,"

      "\"MAIN_IP\":\"%s\","
      "\"MAIN_PORT\":%u,"
      "\"MAIN_EN\":%u,"

      "\"SERVICE_IP\":\"%s\","
      "\"SERVICE_PORT\":%u,"
      "\"SERVICE_EN\":%u,"

      "\"AES_KEY_HEX\":\"%s\""
      "}\n",
      (unsigned)c.NETWORK_ID,
      (unsigned)c.ZONE_ID,
      (unsigned)c.ANCHOR_ID,
      (unsigned)c.HB_MS,
      (unsigned)c.LOG_LEVEL,
      (int)c.TX_ANT_DLY,
      (int)c.RX_ANT_DLY,
      (int)c.BIAS_TICKS,
      (unsigned)c.PHY_CH,
      (unsigned)c.PHY_SFDTO,

      (unsigned)c.GW_ID,

      (unsigned)c.ETH_MODE,
      c.ETH_IP,
      c.ETH_MASK,
      c.ETH_GW,

      c.ZONE_CTRL_IP,
      (unsigned)c.ZONE_CTRL_PORT,
      (unsigned)c.ZONE_CTRL_EN,

      c.MAIN_IP,
      (unsigned)c.MAIN_PORT,
      (unsigned)c.MAIN_EN,

      c.SERVICE_IP,
      (unsigned)c.SERVICE_PORT,
      (unsigned)c.SERVICE_EN,

      c.AES_KEY_HEX
    );
}


// forward deklarációk
static void gcfg_from_globals(void);
static void globals_from_gcfg(void);

static bool parse_str(const char* body, const char* key, char* out, size_t out_sz){
    const char* v = nullptr;
    if (!find_key(body, key, &v)) return false;
    if (*v != '\"') return false;
    v++; // idézőjel után
    const char* end = strchr(v, '\"');
    if (!end) return false;
    size_t len = (size_t)(end - v);
    if (len >= out_sz) len = out_sz - 1;
    memcpy(out, v, len);
    out[len] = 0;
    return true;
}

static bool parse_u32(const char* body, const char* key, uint32_t& out){
    const char* v=nullptr; if(!find_key(body,key,&v)) return false; char* end=nullptr;
    if(*v=='\"') out=strtoul(v+1,&end,16); else out=strtoul(v,&end,10); return true;
}
static bool parse_i32(const char* body, const char* key, int32_t& out){
    const char* v=nullptr; if(!find_key(body,key,&v)) return false; char* end=nullptr;
    if(*v=='\"') out=(int32_t)strtol(v+1,&end,16); else out=(int32_t)strtol(v,&end,10); return true;
}
static bool parse_u16(const char* body, const char* key, uint16_t& out){ uint32_t t; if(!parse_u32(body,key,t)) return false; out=(uint16_t)t; return true; }
static bool parse_u8 (const char* body, const char* key, uint8_t&  out){ uint32_t t; if(!parse_u32(body,key,t)) return false; out=(uint8_t)t;  return true; }

/* ================= /api/config ================= */
static esp_err_t api_config_get(httpd_req_t* req){
    if(!require_role(req, ROLE_BLE)) return ESP_FAIL;
    add_cors(req); add_no_cache(req);
    char buf[512]; json_cfg_print(buf,sizeof(buf),g_cfg);
    httpd_resp_set_type(req,"application/json");
    return httpd_resp_send(req, buf, strlen(buf));
}

static esp_err_t api_config_post(httpd_req_t* req)
{
    if (!require_role(req, ROLE_BLE)) return ESP_FAIL;

    add_cors(req);
    add_no_cache(req);

    int len = req->content_len;
    if (len <= 0) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty");
    }

    std::vector<char> body(len + 1, 0);
    int off = 0;
    while (off < len) {
        int r = httpd_req_recv(req, body.data() + off, len - off);
        if (r <= 0) {
            return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "recv");
        }
        off += r;
    }

    // 1) JSON → g_cfg (csak a benne lévő kulcsok írják felül)
    parse_u16(body.data(), "\"NETWORK_ID\"", g_cfg.NETWORK_ID);
    parse_u16(body.data(), "\"ZONE_ID\""   , g_cfg.ZONE_ID);
    {
        uint32_t t;
        if (parse_u32(body.data(), "\"ANCHOR_ID\"", t)) {
            g_cfg.ANCHOR_ID = t;
        }
    }
    parse_u16(body.data(), "\"HB_MS\""     , g_cfg.HB_MS);
    parse_u8 (body.data(), "\"LOG_LEVEL\"" , g_cfg.LOG_LEVEL);
    parse_i32(body.data(), "\"TX_ANT_DLY\"", g_cfg.TX_ANT_DLY);
    parse_i32(body.data(), "\"RX_ANT_DLY\"", g_cfg.RX_ANT_DLY);
    parse_i32(body.data(), "\"BIAS_TICKS\"", g_cfg.BIAS_TICKS);
    parse_u8 (body.data(), "\"PHY_CH\""    , g_cfg.PHY_CH);
    parse_u16(body.data(), "\"PHY_SFDTO\"" , g_cfg.PHY_SFDTO);

    // ÚJ: GW + 3 IP csoport
    parse_u32(body.data(), "\"GW_ID\"", g_cfg.GW_ID);

    parse_u8 (body.data(), "\"ETH_MODE\"", g_cfg.ETH_MODE);
    parse_str(body.data(), "\"ETH_IP\""   , g_cfg.ETH_IP,   sizeof(g_cfg.ETH_IP));
    parse_str(body.data(), "\"ETH_MASK\"" , g_cfg.ETH_MASK, sizeof(g_cfg.ETH_MASK));
    parse_str(body.data(), "\"ETH_GW\""   , g_cfg.ETH_GW,   sizeof(g_cfg.ETH_GW));

    parse_str(body.data(), "\"ZONE_CTRL_IP\""  , g_cfg.ZONE_CTRL_IP,   sizeof(g_cfg.ZONE_CTRL_IP));
    parse_u16(body.data(), "\"ZONE_CTRL_PORT\"", g_cfg.ZONE_CTRL_PORT);
    parse_u8 (body.data(), "\"ZONE_CTRL_EN\""  , g_cfg.ZONE_CTRL_EN);

    parse_str(body.data(), "\"MAIN_IP\""   , g_cfg.MAIN_IP,   sizeof(g_cfg.MAIN_IP));
    parse_u16(body.data(), "\"MAIN_PORT\"", g_cfg.MAIN_PORT);
    parse_u8 (body.data(), "\"MAIN_EN\""  , g_cfg.MAIN_EN);

    parse_str(body.data(), "\"SERVICE_IP\""  , g_cfg.SERVICE_IP,   sizeof(g_cfg.SERVICE_IP));
    parse_u16(body.data(), "\"SERVICE_PORT\"", g_cfg.SERVICE_PORT);
    parse_u8 (body.data(), "\"SERVICE_EN\""  , g_cfg.SERVICE_EN);

    parse_str(body.data(), "\"AES_KEY_HEX\"", g_cfg.AES_KEY_HEX, sizeof(g_cfg.AES_KEY_HEX));

    // 2) g_cfg → NET / IPS (rendszer-szintű módosítások)
    globals_from_gcfg();

    // 3) tartós mentés NVS-be
    esp_cfg_save_to_nvs();

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}\n");

}

/* NET, IPS -> g_cfg (UI tükör) */
static void gcfg_from_globals(void)
{
    // saját IP
    snprintf(g_cfg.ETH_IP,   sizeof(g_cfg.ETH_IP),   IPSTR, IP2STR(&NET.ip));
    snprintf(g_cfg.ETH_MASK, sizeof(g_cfg.ETH_MASK), IPSTR, IP2STR(&NET.mask));
    snprintf(g_cfg.ETH_GW,   sizeof(g_cfg.ETH_GW),   IPSTR, IP2STR(&NET.gw));
    g_cfg.ETH_MODE = NET.use_dhcp ? 0 : 1;

    // IPS célok → ZONE / MAIN / SERVICE
    snprintf(g_cfg.ZONE_CTRL_IP, sizeof(g_cfg.ZONE_CTRL_IP),
             IPSTR, IP2STR(&IPS.dest[0].dest_ip));
    g_cfg.ZONE_CTRL_PORT = IPS.dest[0].dest_port;
    g_cfg.ZONE_CTRL_EN   = IPS.dest[0].enabled;

    snprintf(g_cfg.MAIN_IP, sizeof(g_cfg.MAIN_IP),
             IPSTR, IP2STR(&IPS.dest[1].dest_ip));
    g_cfg.MAIN_PORT = IPS.dest[1].dest_port;
    g_cfg.MAIN_EN   = IPS.dest[1].enabled;

    snprintf(g_cfg.SERVICE_IP, sizeof(g_cfg.SERVICE_IP),
             IPSTR, IP2STR(&IPS.dest[2].dest_ip));
    g_cfg.SERVICE_PORT = IPS.dest[2].dest_port;
    g_cfg.SERVICE_EN   = IPS.dest[2].enabled;

    g_cfg.GW_ID = IPS.gw_id;
}

/* backwards kompat: ha máshol is hívják */
static void sync_cfg_from_globals(void)
{
    gcfg_from_globals();
}

/* g_cfg -> NET, IPS (rendszer-szintű beállítás) */
static void globals_from_gcfg(void)
{
    NET.use_dhcp = (g_cfg.ETH_MODE == 0);  // 0 = DHCP, 1 = statikus

    ip4addr_aton(g_cfg.ETH_IP,   &NET.ip);
    ip4addr_aton(g_cfg.ETH_MASK, &NET.mask);
    ip4addr_aton(g_cfg.ETH_GW,   &NET.gw);

    IPS.gw_id = g_cfg.GW_ID;

    ip4addr_aton(g_cfg.ZONE_CTRL_IP, &IPS.dest[0].dest_ip);
    IPS.dest[0].dest_port = g_cfg.ZONE_CTRL_PORT;
    IPS.dest[0].enabled   = g_cfg.ZONE_CTRL_EN;

    ip4addr_aton(g_cfg.MAIN_IP, &IPS.dest[1].dest_ip);
    IPS.dest[1].dest_port = g_cfg.MAIN_PORT;
    IPS.dest[1].enabled   = g_cfg.MAIN_EN;

    ip4addr_aton(g_cfg.SERVICE_IP, &IPS.dest[2].dest_ip);
    IPS.dest[2].dest_port = g_cfg.SERVICE_PORT;
    IPS.dest[2].enabled   = g_cfg.SERVICE_EN;

    // AES kulcs (ha meg van adva)
    if (g_cfg.AES_KEY_HEX[0] != '\0') {
        aes_sender_set_key_hex(g_cfg.AES_KEY_HEX);
    }

}

/* ================= /api/status ================= */
extern net_config_t NET;
extern ips_config_t IPS;
extern volatile int eth_up;   // ha máshol nem kell, ezt akár el is hagyhatod
extern volatile int ble_up;

static esp_err_t api_status_get(httpd_req_t* req){
    add_cors(req);
    add_no_cache(req);

    const char* st = (g_status.state==ST_OK   ? "ok"   :
                      g_status.state==ST_WARN ? "warn" :
                      g_status.state==ST_ERR  ? "err"  : "off");

    bool eth_ok = (NET.ip.addr != 0);

    char buf[256];
    int n = snprintf(buf, sizeof(buf),
        "{"
          "\"anchor\":\"%s\","
          "\"id\":%u,"
          "\"last_s\":%.2f,"
          "\"last_v\":%.2f,"
          "\"state\":\"%s\","
          "\"eth_up\":%d,"
          "\"ble_up\":%d,"
          "\"zone_en\":%u,"
          "\"main_en\":%u,"
          "\"service_en\":%u"
        "}\n",
        g_status.anchor,
        g_status.id,
        g_status.last_meas_s,
        g_status.last_volt,
        st,
        eth_ok ? 1 : 0,
        ble_up,
        (unsigned)IPS.dest[0].enabled,
        (unsigned)IPS.dest[1].enabled,
        (unsigned)IPS.dest[2].enabled
    );

    httpd_resp_set_type(req,"application/json");
    return httpd_resp_send(req, buf, n);
}

/* ================= Server start/stop ================= */
esp_err_t webserver_start(){
    if (s_http) return ESP_OK;

    /* 1) próbáljuk NVS-ből betölteni az ESP configot */
    bool have_nvs_cfg = esp_cfg_load_from_nvs();

    if (have_nvs_cfg) {
        /* 2a) ha volt mentett cfg, azt tekintjük igaznak:
               g_cfg -> NET/IPS */
        globals_from_gcfg();
    } else {
        /* 2b) ha nincs NVS, indulunk a compile-time default NET/IPS-ből,
               és abból gyártunk g_cfg-et a UI-nak */
        gcfg_from_globals();
        /* opcionális: ezt az alapot is elmentheted NVS-be, ha szeretnéd */
        // esp_cfg_save_to_nvs();
    }

    aes_sender_init();

    if (g_cfg.AES_KEY_HEX[0] != '\0') {
        aes_sender_set_key_hex(g_cfg.AES_KEY_HEX);
    }

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.uri_match_fn = httpd_uri_match_wildcard;
    cfg.max_uri_handlers = 24;
    cfg.stack_size = 8192;

    ESP_ERROR_CHECK(httpd_start(&s_http, &cfg));

    // BLE bridge
    ble_http_bridge_init();
    http_register_routes(s_http);   // /api/dwm_get

    // Pages
    httpd_uri_t u{};
    u.method=HTTP_GET;
    u.uri="/login";            u.handler=login_get;        httpd_register_uri_handler(s_http,&u);
    u.uri="/diag";             u.handler=diag_get;         httpd_register_uri_handler(s_http,&u);
    u.uri="/ble-data";         u.handler=ble_get;          httpd_register_uri_handler(s_http,&u);
    u.uri="/admin";            u.handler=admin_get;        httpd_register_uri_handler(s_http,&u);
    u.uri="/super_user.html";  u.handler=super_user_get;   httpd_register_uri_handler(s_http,&u);

    // API GET-ek
    u.uri="/api/status";       u.handler=api_status_get;   httpd_register_uri_handler(s_http,&u);
    httpd_uri_t get_cfg{};  get_cfg.method=HTTP_GET;    get_cfg.uri="/api/config";   get_cfg.handler=api_config_get;
    httpd_register_uri_handler(s_http,&get_cfg);

    // API POST-ok
    httpd_uri_t post_cfg{}; post_cfg.method=HTTP_POST;  post_cfg.uri="/api/config";  post_cfg.handler=api_config_post;
    httpd_register_uri_handler(s_http,&post_cfg);

    // AUTH: POST + OPTIONS (preflight)
    httpd_uri_t auth_post{}; auth_post.method=HTTP_POST;    auth_post.uri="/auth/login";    auth_post.handler=auth_login_post;
    httpd_register_uri_handler(s_http,&auth_post);

    // Preflight OPTIONS minden érintett útvonalra
    httpd_uri_t opt{};
    opt.method=HTTP_OPTIONS;  opt.uri="/auth/login";   opt.handler=options_ok; httpd_register_uri_handler(s_http,&opt);
    opt.uri="/api/config";    httpd_register_uri_handler(s_http,&opt);
    opt.uri="/api/status";    httpd_register_uri_handler(s_http,&opt);
    opt.uri="/api/dwm_get";   httpd_register_uri_handler(s_http,&opt);

    // Root és catch-all → login
    httpd_uri_t root{}; root.method=HTTP_GET; root.uri="/";  root.handler=login_get; httpd_register_uri_handler(s_http,&root);
    httpd_uri_t any{};  any .method=HTTP_GET; any .uri="/*"; any .handler=login_get; httpd_register_uri_handler(s_http,&any);

    ESP_LOGI(TAG,"webserver started");

    if (s_http != nullptr) {
        http_register_routes(s_http);   // <-- itt húzza be a /api/dwm_get és /api/dwm_set route-okat
    }

    return ESP_OK;
}

esp_err_t webserver_stop(){
    if(!s_http) return ESP_OK;
    httpd_stop(s_http); s_http=nullptr; return ESP_OK;
}
