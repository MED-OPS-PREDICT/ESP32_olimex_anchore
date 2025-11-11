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
} g_cfg;

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
      "\"PHY_SFDTO\":%u"
      "}\n",
      (unsigned)c.NETWORK_ID,(unsigned)c.ZONE_ID,(unsigned)c.ANCHOR_ID,
      (unsigned)c.HB_MS,(unsigned)c.LOG_LEVEL,
      (int)c.TX_ANT_DLY,(int)c.RX_ANT_DLY,(int)c.BIAS_TICKS,
      (unsigned)c.PHY_CH,(unsigned)c.PHY_SFDTO);
}
static bool find_key(const char* body, const char* key, const char** val_start){
    const char* p=strstr(body,key); if(!p) return false;
    p=strchr(p,':'); if(!p) return false; p++;
    while(*p==' '||*p=='\"'){ if(*p=='\"'){ *val_start=p; return true; } ++p; }
    *val_start=p; return true;
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
    char buf[256]; json_cfg_print(buf,sizeof(buf),g_cfg);
    httpd_resp_set_type(req,"application/json");
    return httpd_resp_send(req, buf, strlen(buf));
}
static esp_err_t api_config_post(httpd_req_t* req){
    if(!require_role(req, ROLE_BLE)) return ESP_FAIL;
    add_cors(req); add_no_cache(req);
    int len=req->content_len; if(len<=0) return httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"empty");
    std::vector<char> body(len+1,0); int off=0;
    while(off<len){ int r=httpd_req_recv(req,body.data()+off,len-off); if(r<=0) return httpd_resp_send_err(req,HTTPD_500_INTERNAL_SERVER_ERROR,"recv"); off+=r; }
    parse_u16(body.data(),"\"NETWORK_ID\"",g_cfg.NETWORK_ID);
    parse_u16(body.data(),"\"ZONE_ID\""   ,g_cfg.ZONE_ID);
    { uint32_t t; if(parse_u32(body.data(),"\"ANCHOR_ID\"",t)) g_cfg.ANCHOR_ID=t; }
    parse_u16(body.data(),"\"HB_MS\""     ,g_cfg.HB_MS);
    parse_u8 (body.data(),"\"LOG_LEVEL\"" ,g_cfg.LOG_LEVEL);
    parse_i32(body.data(),"\"TX_ANT_DLY\"",g_cfg.TX_ANT_DLY);
    parse_i32(body.data(),"\"RX_ANT_DLY\"",g_cfg.RX_ANT_DLY);
    parse_i32(body.data(),"\"BIAS_TICKS\"",g_cfg.BIAS_TICKS);
    parse_u8 (body.data(),"\"PHY_CH\""    ,g_cfg.PHY_CH);
    parse_u16(body.data(),"\"PHY_SFDTO\"" ,g_cfg.PHY_SFDTO);
    httpd_resp_set_type(req,"application/json");
    return httpd_resp_sendstr(req,"{\"ok\":true}\n");
}

/* ================= /api/status ================= */
static esp_err_t api_status_get(httpd_req_t* req){
    add_cors(req); add_no_cache(req);
    const char* st = (g_status.state==ST_OK?"ok":g_status.state==ST_WARN?"warn":g_status.state==ST_ERR?"err":"off");
    char buf[128];
    int n=snprintf(buf,sizeof(buf),
        "{\"anchor\":\"%s\",\"id\":%u,\"last_s\":%.2f,\"last_v\":%.2f,\"state\":\"%s\"}\n",
        g_status.anchor,g_status.id,g_status.last_meas_s,g_status.last_volt,st);
    httpd_resp_set_type(req,"application/json");
    return httpd_resp_send(req,buf,n);
}

/* ================= Server start/stop ================= */
esp_err_t webserver_start(){
    if (s_http) return ESP_OK;

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.uri_match_fn = httpd_uri_match_wildcard;
    cfg.max_uri_handlers = 24;
    cfg.stack_size = 8192;      // nagyobb stack

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
    return ESP_OK;
}

esp_err_t webserver_stop(){
    if(!s_http) return ESP_OK;
    httpd_stop(s_http); s_http=nullptr; return ESP_OK;
}
