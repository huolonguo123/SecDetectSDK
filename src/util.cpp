/*
 * util.cpp — 检测器公共取证工具
 *
 * 原则:全部基于公开可读的 /proc、系统属性、文件系统,零第三方依赖;
 *       每个函数只做一件小事,检测子类组合使用。
 */
#include "internal.h"

#include <dirent.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

namespace sec {
namespace util {

/* ================= 文件 ================= */

bool file_exists(const char* path) {
    struct stat st;
    return path && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

bool file_executable(const char* path) {
    return path && access(path, X_OK) == 0;
}

bool path_exists(const char* path) {
    return path && access(path, F_OK) == 0;
}

void list_dir(const char* path, std::vector<std::string>& out) {
    DIR* d = opendir(path);
    if (!d) return;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        out.emplace_back(e->d_name);
    }
    closedir(d);
}

bool read_small_file(const char* path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool read_small_file(const char* path, std::vector<uint8_t>& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

/* ================= /proc/<pid>/... 目标进程取证 =================
 * pid <= 0 一律表示"自己"(/proc/self)——runner / App 集成默认;
 * pid > 0 读 /proc/<pid>/...:扫描别的进程需要 root 或同 uid,
 * App 沙盒默认被 SELinux 挡。检测 input 形如 "pid:1234"。       */

static std::string proc_file(int pid, const char* leaf) {
    char buf[64];
    if (pid <= 0) snprintf(buf, sizeof buf, "/proc/self/%s", leaf);
    else          snprintf(buf, sizeof buf, "/proc/%d/%s", pid, leaf);
    return buf;
}

int target_pid(const char* input) {
    if (input && strncmp(input, "pid:", 4) == 0) return atoi(input + 4);
    return 0;
}

int tracer_pid_of(int pid) {
    std::string s;
    if (!read_small_file(proc_file(pid, "status").c_str(), s)) return 0;
    /* 行格式:"TracerPid:\t1234\n" */
    const char* p = strstr(s.c_str(), "TracerPid:");
    if (!p) return 0;
    p += strlen("TracerPid:");
    while (*p == ' ' || *p == '\t') ++p;
    return atoi(p);
}

std::string exe_of(int pid) {
    std::string link = proc_file(pid, "exe");
    char buf[512];
    ssize_t n = readlink(link.c_str(), buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    return buf;
}

std::string maps_of(int pid) {
    std::string s;
    if (!read_small_file(proc_file(pid, "maps").c_str(), s)) return {};
    return s;
}

/* 目标进程是否存在(pid<=0 恒真:自己必然在) */
bool process_exists(int pid) {
    if (pid <= 0) return true;
    char buf[64];
    snprintf(buf, sizeof buf, "/proc/%d", pid);
    return access(buf, F_OK) == 0;
}

bool maps_path_contains(int pid, const char* keyword) {
    std::string s = maps_of(pid);
    if (s.empty()) return false;
    const char* p = s.c_str();
    while (p && *p) {
        const char* eol = strchr(p, '\n');
        std::string line(p, eol ? eol - p : strlen(p));
        /* 行:start-end perms offset dev inode pathname
         * 跳 5 个空白分隔字段,剩下的整段是 pathname(可能含空格) */
        int fields = 0;
        const char* t = line.c_str();
        while (fields < 5) {
            while (*t == ' ') ++t;
            if (!*t) break;
            t = strchr(t, ' ');
            if (!t) break;
            ++fields;
        }
        while (*t == ' ') ++t;
        if (*t && strstr(t, keyword)) return true;
        p = eol ? eol + 1 : nullptr;
    }
    return false;
}

/* ================= /proc/net/tcp:端口监听 ================= */

static bool tcp4or6_listening(const char* file, uint16_t port) {
    std::string s;
    if (!read_small_file(file, s)) return false;
    char needle[16];
    snprintf(needle, sizeof needle, ":%04X", port);  /* tcp 表端口是小端 hex,如 27042 -> 69A2 */

    const char* p = s.c_str();
    while (p && *p) {
        const char* eol = strchr(p, '\n');
        std::string line(p, eol ? eol - p : strlen(p));
        /* 找 local_address 列:第二个空白分隔字段 */
        const char* t = line.c_str();
        while (*t == ' ') ++t;
        t = strchr(t, ' ');                 // 跳过 sl
        if (!t) break;
        while (*t == ' ') ++t;
        /* 现在 t 指向 local_address(形如 0100007F:69A2) */
        const char* colon = strchr(t, ':');
        const char* sp = strchr(t, ' ');
        if (colon && (!sp || colon < sp)) {
            /* local 端口匹配 → 看状态列(st 在 remote_address 之后) */
            const char* st = sp ? sp : t + strlen(t);
            while (*st == ' ') ++st;
            if (strncmp(st, "0A", 2) == 0 &&          /* 0A = LISTEN */
                strncmp(colon + 1, needle, 4) == 0)
                return true;
        }
        p = eol ? eol + 1 : nullptr;
    }
    return false;
}

bool tcp_port_listening(uint16_t port) {
    return tcp4or6_listening("/proc/net/tcp", port) ||
           tcp4or6_listening("/proc/net/tcp6", port);
}

/* ================= /proc/<pid>/cmdline 遍历 ================= */

static bool is_pid_dir(const char* name) {
    if (!*name) return false;
    for (const char* c = name; *c; ++c)
        if (*c < '0' || *c > '9') return false;
    return true;
}

bool any_process_cmdline_contains(const char* keyword) {
    DIR* d = opendir("/proc");
    if (!d) return false;
    struct dirent* e;
    bool hit = false;
    while (!hit && (e = readdir(d)) != nullptr) {
        if (!is_pid_dir(e->d_name)) continue;
        if (strcmp(e->d_name, "self") == 0) continue;  // 自身不算
        char path[64];
        snprintf(path, sizeof path, "/proc/%s/cmdline", e->d_name);
        std::string cmd;
        if (read_small_file(path, cmd) && !cmd.empty()) {
            /* cmdline 各参数以 '\0' 分隔;统一替换成空格再搜,防跨参数误拼 */
            for (auto& c : cmd) if (c == '\0') c = ' ';
            hit = cmd.find(keyword) != std::string::npos;
        }
    }
    closedir(d);
    return hit;
}

/* ================= 系统属性 ================= */

std::string get_prop(const char* name) {
    char buf[PROP_VALUE_MAX];
    int n = __system_property_get(name, buf);
    if (n <= 0) return std::string();
    return std::string(buf, (size_t)n);
}

/* ================= popen 首行 ================= */

std::string first_line_of(const char* cmd) {
    FILE* fp = popen(cmd, "r");
    if (!fp) return std::string();
    char line[512];
    bool ok = fgets(line, sizeof line, fp) != nullptr;
    pclose(fp);
    if (!ok) return std::string();
    size_t n = strlen(line);
    while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
    return std::string(line, n);
}

/* ================= SHA-256(FIPS 180-4,零依赖) ================= */

namespace {

const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

struct Sha256 {
    uint32_t h[8];
    uint64_t total;   // 已处理字节数
    uint8_t buf[64];
    size_t buflen;

    Sha256() {
        h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
        h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
        total = 0; buflen = 0;
    }

    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void block(const uint8_t* p) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
                   (uint32_t)p[i * 4 + 2] << 8 | p[i * 4 + 3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K256[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    void update(const uint8_t* data, size_t len) {
        total += len;
        while (len) {
            size_t take = 64 - buflen;
            if (take > len) take = len;
            memcpy(buf + buflen, data, take);
            buflen += take; data += take; len -= take;
            if (buflen == 64) { block(buf); buflen = 0; }
        }
    }

    void final(uint8_t out[32]) {
        uint64_t bits = total * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buflen != 56) update(&zero, 1);   // 补到 56 字节(留 8 字节长度)
        uint8_t lenb[8];
        for (int i = 0; i < 8; ++i) lenb[i] = (uint8_t)(bits >> (56 - i * 8));
        update(lenb, 8);
        for (int i = 0; i < 8; ++i) {
            out[i * 4]     = (uint8_t)(h[i] >> 24);
            out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
            out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
            out[i * 4 + 3] = (uint8_t)h[i];
        }
    }
};

}  // namespace

std::string sha256_hex(const uint8_t* data, size_t len) {
    Sha256 ctx;
    ctx.update(data, len);
    uint8_t d[32];
    ctx.final(d);
    static const char* hx = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 32; ++i) {
        out.push_back(hx[d[i] >> 4]);
        out.push_back(hx[d[i] & 0xf]);
    }
    return out;
}

std::string sha256_file_hex(const char* path) {
    std::vector<uint8_t> data;
    if (!read_small_file(path, data)) return std::string();
    return sha256_hex(data.data(), data.size());
}

/* ================= 简易 ZIP 定位(APK 的 META-INF v1 签名块) ================= */

static uint16_t rd16(const uint8_t* p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static bool has_suffix(const std::string& s, const char* suf) {
    size_t n = strlen(suf);
    return s.size() >= n && s.compare(s.size() - n, n, suf) == 0;
}

bool apk_first_signature(const char* apk_path, std::vector<uint8_t>& out) {
    FILE* fp = fopen(apk_path, "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    if (fsize < 22) { fclose(fp); return false; }

    /* --- 1. 定位 EOCD:文件尾部 22+comment(≤64KB)内找 0x06054b50 --- */
    long tail = fsize < (22 + 65535) ? fsize : (22 + 65535);
    std::vector<uint8_t> buf((size_t)tail);
    fseek(fp, fsize - tail, SEEK_SET);
    if (fread(buf.data(), 1, buf.size(), fp) != buf.size()) { fclose(fp); return false; }

    long eocd_off = -1;
    for (long i = (long)buf.size() - 22; i >= 0; --i) {
        if (rd32(&buf[(size_t)i]) == 0x06054b50) {
            uint16_t clen = rd16(&buf[(size_t)i + 20]);
            if (i + 22 + clen == (long)buf.size()) { eocd_off = i; break; }  // comment 长度吻合
        }
    }
    if (eocd_off < 0) { fclose(fp); return false; }

    const uint8_t* eocd = &buf[(size_t)eocd_off];
    uint16_t total_entries = rd16(eocd + 10);
    uint32_t cd_offset     = rd32(eocd + 16);
    if (total_entries == 0 || cd_offset >= (uint32_t)fsize) { fclose(fp); return false; }

    /* --- 2. 遍历 Central Directory,找 META-INF 下的 .RSA/.DSA/.EC --- */
    std::vector<uint8_t> cd;
    fseek(fp, cd_offset, SEEK_SET);
    cd.resize(64 * 1024);
    size_t cd_read = fread(cd.data(), 1, cd.size(), fp);   // 目录区一般远小于 64KB
    size_t pos = 0;
    int found = -1;
    for (int e = 0; e < total_entries && pos + 46 <= cd_read; ++e) {
        if (rd32(&cd[pos]) != 0x02014b50) break;           // 不是 CD 头,异常退出
        uint16_t nlen = rd16(&cd[pos + 28]);
        uint16_t elen = rd16(&cd[pos + 30]);
        uint16_t clen = rd16(&cd[pos + 32]);
        if (pos + 46 + nlen > cd_read) break;
        std::string name((const char*)&cd[pos + 46], nlen);
        if (name.find("META-INF/") == 0 &&
            (has_suffix(name, ".RSA") || has_suffix(name, ".DSA") || has_suffix(name, ".EC"))) {
            found = (int)e;
            /* 记录本条目字段,直接 break */
            uint16_t method = rd16(&cd[pos + 10]);
            uint32_t csize  = rd32(&cd[pos + 20]);
            uint32_t usize  = rd32(&cd[pos + 24]);
            uint32_t lho    = rd32(&cd[pos + 42]);

            /* --- 3. 跳到 Local File Header,读数据 --- */
            std::vector<uint8_t> lh;
            fseek(fp, lho, SEEK_SET);
            lh.resize(30);
            if (fread(lh.data(), 1, 30, fp) != 30) break;
            if (rd32(lh.data()) != 0x04034b50) break;
            uint16_t l_nlen = rd16(&lh.data()[26]);
            uint16_t l_elen = rd16(&lh.data()[28]);

            std::vector<uint8_t> comp;
            fseek(fp, (long)lho + 30 + l_nlen + l_elen, SEEK_SET);
            comp.resize(csize ? csize : 1);
            if (csize && fread(comp.data(), 1, csize, fp) != csize) break;

            if (method == 0) {                     // stored:原样
                out = std::move(comp);
                found = 0;
            } else if (method == 8) {              // deflate:inflate
#ifdef HAVE_ZLIB
                if (usize > 4 * 1024 * 1024) break;   // 防恶意巨大声明
                out.resize(usize ? usize : 1);
                uLongf dl = usize;
                int zr = uncompress(out.data(), &dl, comp.data(), (uLong)csize);
                if (zr != Z_OK) break;
                out.resize(dl);
                found = 0;
#else
                (void)usize;
#endif
            }
            break;   // 找到第一个签名块后不管成没成,退出循环
        }
        pos += 46 + nlen + elen + clen;
    }
    fclose(fp);
    return found == 0 && !out.empty();
}

/* ================= base16 解码 ================= */

bool hex_decode(const char* hex, std::vector<uint8_t>& out) {
    if (!hex) return false;
    size_t n = strlen(hex);
    if (n % 2) return false;
    out.clear();
    out.reserve(n / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < n; i += 2) {
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

}  // namespace util
}  // namespace sec
