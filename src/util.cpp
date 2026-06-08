/*
 * util.cpp — 检测器公共取证工具
 *
 * 原则:全部基于公开可读的 /proc、系统属性、文件系统,零第三方依赖;
 *       每个函数只做一件小事,检测子类组合使用。
 */
#include "internal.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

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
        char path[300];
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

/* 解 ZIP 里的 deflate 数据。注意:ZIP 用的是**裸 deflate**(没有 zlib
 * 的 2 字节头与 adler32 尾),所以不能用 uncompress(),必须
 * inflateInit2(&strm, -MAX_WBITS)。(这一步以前用错 API,v1 签名
 * 文件(默认 deflate 压缩)永远解不出来 —— 修于 v1.1.0。) */
static bool inflate_raw(const uint8_t* src, size_t srclen, size_t expected,
                        std::vector<uint8_t>& out) {
#ifdef HAVE_ZLIB
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) return false;
    zs.next_in = (Bytef*)src;
    zs.avail_in = (uInt)srclen;

    size_t cap = expected ? expected : 64 * 1024;
    out.resize(cap);
    zs.next_out = out.data();
    zs.avail_out = (uInt)out.size();

    int r = Z_OK;
    while (true) {
        r = inflate(&zs, Z_FINISH);
        if (r == Z_STREAM_END) break;
        if (r == Z_OK || r == Z_BUF_ERROR) {
            if (zs.avail_out != 0) {           /* 输入耗尽但流没结束 → 坏数据 */
                inflateEnd(&zs);
                return false;
            }
            size_t used = out.size();
            if (used > 64ULL * 1024 * 1024) {  /* 防解压炸弹 */
                inflateEnd(&zs);
                return false;
            }
            out.resize(used * 2);
            zs.next_out = out.data() + used;
            zs.avail_out = (uInt)(out.size() - used);
            continue;
        }
        inflateEnd(&zs);
        return false;
    }
    size_t total = zs.total_out;
    inflateEnd(&zs);
    out.resize(total);
    return true;
#else
    (void)src; (void)srclen; (void)expected; (void)out;
    return false;
#endif
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
    uint32_t cd_size       = rd32(eocd + 12);
    if (total_entries == 0 || cd_offset >= (uint32_t)fsize) { fclose(fp); return false; }

    /* --- 2. 遍历 Central Directory,找 META-INF 下的 .RSA/.DSA/.EC ---
     * 目录区大小以 EOCD 的 cd_size 为准(以前硬编码 64KB,
     * 大 APK(几千个条目)的目录区会超,导致找不到签名文件) */
    if (cd_size == 0 || cd_offset + cd_size > (uint32_t)fsize) cd_size = (uint32_t)(fsize - cd_offset);
    if (cd_size > 8u * 1024 * 1024) cd_size = 8u * 1024 * 1024;   // 防呆上限 8MB
    std::vector<uint8_t> cd;
    fseek(fp, cd_offset, SEEK_SET);
    cd.resize(cd_size);
    size_t cd_read = fread(cd.data(), 1, cd.size(), fp);
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
            } else if (method == 8) {              // deflate:裸 deflate 解压
                if (usize > 4 * 1024 * 1024) break;   // 防恶意巨大声明
                if (inflate_raw(comp.data(), csize, usize, out)) found = 0;
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

/* ====================================================================
 * v1.1.0 追加:结构化分析原语(maps / 内存 / 线程 / 端口 / 属性 / sysfs)
 * ==================================================================== */

/* 读文件第一行(sysfs 节点常用) */
std::string read_line_file(const char* path) {
    FILE* fp = fopen(path, "r");
    if (!fp) return std::string();
    char line[256];
    bool ok = fgets(line, sizeof line, fp) != nullptr;
    fclose(fp);
    if (!ok) return std::string();
    size_t n = strlen(line);
    while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
    return std::string(line, n);
}

std::string proc_read(int pid, const char* leaf) {
    std::string s;
    read_small_file(proc_file(pid, leaf).c_str(), s);
    return s;
}

/* maps 行:start-end perms offset dev inode pathname
 * 用 sscanf 一次拿 4 个字段 + %n 记录已消费长度,剩下的就是 pathname
 * (pathname 可含空格,不能按空格切)。 */
bool parse_maps(int pid, std::vector<MapRegion>& out) {
    std::string s = maps_of(pid);
    if (s.empty()) return false;
    const char* p = s.c_str();
    while (p && *p) {
        const char* eol = strchr(p, '\n');
        std::string line(p, eol ? (size_t)(eol - p) : strlen(p));
        p = eol ? eol + 1 : nullptr;

        unsigned long long st = 0, en = 0, off = 0;
        char perms[8] = {0};
        int consumed = 0;
        int got = sscanf(line.c_str(), "%llx-%llx %4s %llx %*s %*s%n",
                         &st, &en, perms, &off, &consumed);
        if (got < 4) continue;

        MapRegion r;
        r.start = st;
        r.end = en;
        r.off = off;
        memcpy(r.perms, perms, 4);
        r.perms[4] = '\0';
        if (consumed > 0 && (size_t)consumed < line.size()) {
            std::string path = line.substr((size_t)consumed);
            size_t b = path.find_first_not_of(' ');
            path = (b == std::string::npos) ? std::string() : path.substr(b);
            size_t d = path.find(" (deleted)");
            if (d != std::string::npos) {
                r.deleted = true;       /* 保留标记:det_module/integrity 要分开处理 */
                path.erase(d);
            }
            r.path = path;
        }
        out.push_back(std::move(r));
    }
    return !out.empty();
}

/* 读目标进程内存:/proc/<pid>/mem 的 pread。跨未映射页会短读/EIO,
 * 调用方按"完整映射区间内"的块来读就不会踩到。 */
bool read_proc_mem(int pid, uint64_t addr, void* buf, size_t len) {
    std::string path = proc_file(pid, "mem");
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    uint8_t* dst = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread(fd, dst + done, len - done, (off_t)(addr + done));
        if (n <= 0) break;
        done += (size_t)n;
    }
    close(fd);
    return done == len;
}

void list_thread_comms(int pid, std::vector<std::string>& out) {
    char dir[64];
    if (pid <= 0) snprintf(dir, sizeof dir, "/proc/self/task");
    else          snprintf(dir, sizeof dir, "/proc/%d/task", pid);
    std::vector<std::string> tids;
    list_dir(dir, tids);
    for (const auto& t : tids) {
        char p[96];
        snprintf(p, sizeof p, "%s/%s/comm", dir, t.c_str());
        std::string c = read_line_file(p);
        if (!c.empty()) out.push_back(c);
    }
}

/* 内存字符串扫描:逐映射、按块读,块间保留 needle-1 字节重叠,
 * 这样跨块边界的特征串也能命中。总量由 max_bytes 兜底防卡死。
 * 多特征版本:一遍内存里对窗口跑 N 次 memmem(魔改版要同时找
 * 明文/base64/自定义特征,不能扫 N 遍全量内存)。 */
/* 当前模块(我们自己所在的 .so/可执行文件)的路径。
 * 为什么需要:内存特征扫描用的 needle 常量("frida:rpc" 之类)**本身就活在我们
 * 自己的 .rodata 里**,而扫描会遍历所有可读映射 —— 不排除必然自命中。
 * 实测(2026-09 宿主冒烟):扫自己 → 命中 "frida:rpc" @ 自己的二进制地址,
 * 真机上就等于"每次跑都误报 frida"。所以按路径把自身模块整块跳过。 */
static std::string own_module_path() {
    static std::string cached;
    if (!cached.empty()) return cached;
    uintptr_t self = reinterpret_cast<uintptr_t>(reinterpret_cast<void*>(&own_module_path));
    std::vector<MapRegion> maps;
    if (!parse_maps(0, maps)) return cached;          /* 0 = 自己 */
    for (const MapRegion& r : maps) {
        if (self >= r.start && self < r.end) { cached = r.path; break; }
    }
    return cached;
}

/* 两个路径是否指向同一个模块(Android linker 可能给出相对名) */
static bool same_module(const std::string& a, const std::string& b) {
    if (a.empty() || b.empty()) return false;
    if (a == b) return true;
    size_t sa = a.find_last_of('/'), sb = b.find_last_of('/');
    const char* na = (sa == std::string::npos) ? a.c_str() : a.c_str() + sa + 1;
    const char* nb = (sb == std::string::npos) ? b.c_str() : b.c_str() + sb + 1;
    return std::string(na) == std::string(nb);
}

bool mem_scan_any(int pid, const char* const* needles, size_t nneedles,
                  uint64_t max_bytes, const char** hit, uint64_t* hit_addr,
                  std::string* region) {
    if (!needles || nneedles == 0) return false;
    size_t maxlen = 1;
    for (size_t i = 0; i < nneedles; ++i) {
        if (!needles[i] || !*needles[i]) continue;
        size_t l = strlen(needles[i]);
        if (l > maxlen) maxlen = l;
    }
    std::vector<MapRegion> maps;
    if (!parse_maps(pid, maps)) return false;
    const std::string own = own_module_path();

    uint64_t budget = max_bytes;
    std::vector<uint8_t> tail, buf;
    for (const MapRegion& r : maps) {
        if (budget == 0) break;
        if (!r.is_read() || r.end <= r.start) continue;
        /* ★ 排除自身模块:needle 常量在那里,扫它 = 自己命中自己 */
        if (!own.empty() && same_module(r.path, own)) continue;
        uint64_t cap = std::min<uint64_t>(r.end - r.start, budget);
        uint64_t va = r.start;
        tail.clear();
        while (va < r.start + cap) {
            size_t want = (size_t)std::min<uint64_t>(64 * 1024, r.start + cap - va);
            buf.resize(want);
            if (read_proc_mem(pid, va, buf.data(), want)) {
                std::vector<uint8_t> win;
                win.reserve(tail.size() + want);
                win.insert(win.end(), tail.begin(), tail.end());
                win.insert(win.end(), buf.begin(), buf.end());
                for (size_t i = 0; i < nneedles; ++i) {
                    if (!needles[i] || !*needles[i]) continue;
                    void* fp = memmem(win.data(), win.size(), needles[i], strlen(needles[i]));
                    if (fp) {
                        if (hit) *hit = needles[i];
                        if (hit_addr)
                            *hit_addr = va - tail.size() + (uint64_t)((uint8_t*)fp - win.data());
                        if (region) *region = r.path;
                        return true;
                    }
                }
                if (maxlen > 1)
                    tail.assign(win.end() - (maxlen - 1), win.end());
                else
                    tail.clear();
            } else {
                tail.clear();
            }
            budget -= (budget > want) ? want : budget;
            va += want;
        }
    }
    return false;
}

bool mem_scan_string(int pid, const char* needle, uint64_t max_bytes,
                     uint64_t* hit_addr, std::string* region) {
    const char* needles[1] = {needle};
    return mem_scan_any(pid, needles, 1, max_bytes, nullptr, hit_addr, region);
}

/* ---------------- 监听端口 + 归属进程 ---------------- */

static std::string cmdline_of_pid(const std::string& pid) {
    std::string cmd = proc_read(atoi(pid.c_str()), "cmdline");
    for (auto& c : cmd) if (c == '\0') c = ' ';
    size_t e = cmd.find_last_not_of(' ');
    if (e != std::string::npos) cmd.erase(e + 1);
    return cmd;
}

/* 从 /proc/net/tcp{,6} 收 LISTEN 行的 inode,再遍历各进程的 fd 目录反查
 * 归属进程。frida-server 随机端口、IDA 改端口都能靠这招抓到。 */
void list_listening_ports(std::vector<ListenPort>& out) {
    std::vector<std::pair<uint16_t, std::string>> listen_inodes;  // (port, inode)
    for (const char* f : {"/proc/net/tcp", "/proc/net/tcp6"}) {
        std::string s;
        if (!read_small_file(f, s)) continue;
        const char* p = s.c_str();
        while (p && *p) {
            const char* eol = strchr(p, '\n');
            std::string line(p, eol ? (size_t)(eol - p) : strlen(p));
            p = eol ? eol + 1 : nullptr;

            /* 字段:sl local rem st tx:rx tr:tm retr uid timeout inode */
            std::vector<std::string> tok;
            size_t i = 0;
            while (i < line.size() && tok.size() < 10) {
                size_t b = line.find_first_not_of(" \t", i);
                if (b == std::string::npos) break;
                size_t e = line.find_first_of(" \t", b);
                tok.push_back(line.substr(b, (e == std::string::npos) ? std::string::npos : e - b));
                if (e == std::string::npos) break;
                i = e;
            }
            if (tok.size() < 10) continue;
            if (tok[3] != "0A") continue;                     /* 0A = LISTEN */
            size_t colon = tok[1].rfind(':');
            if (colon == std::string::npos) continue;
            uint16_t port = (uint16_t)strtoul(tok[1].c_str() + colon + 1, nullptr, 16);
            listen_inodes.emplace_back(port, tok[9]);
        }
    }
    if (listen_inodes.empty()) return;

    std::map<std::string, int> inode_pid;
    DIR* d = opendir("/proc");
    if (!d) return;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (!is_pid_dir(e->d_name)) continue;
        int pid = atoi(e->d_name);
        std::string fd_dir = std::string("/proc/") + e->d_name + "/fd";
        std::vector<std::string> fds;
        list_dir(fd_dir.c_str(), fds);
        for (const auto& fd : fds) {
            char link[96];
            snprintf(link, sizeof link, "%s/%s", fd_dir.c_str(), fd.c_str());
            char tgt[128];
            ssize_t n = readlink(link, tgt, sizeof(tgt) - 1);
            if (n <= 0) continue;
            tgt[n] = '\0';
            if (strncmp(tgt, "socket:[", 8) != 0) continue;
            std::string ino(tgt + 8);
            size_t rb = ino.find(']');
            if (rb != std::string::npos) ino.erase(rb);
            inode_pid.emplace(ino, pid);
        }
    }
    closedir(d);

    for (const auto& li : listen_inodes) {
        ListenPort lp;
        lp.port = li.first;
        auto it = inode_pid.find(li.second);
        if (it != inode_pid.end()) {
            lp.pid = it->second;
            char pidstr[16];
            snprintf(pidstr, sizeof pidstr, "%d", it->second);
            lp.owner = cmdline_of_pid(pidstr);
            if (lp.owner.empty()) {
                char comm[16];
                snprintf(comm, sizeof comm, "%d", it->second);
                lp.owner = read_line_file((std::string("/proc/") + comm + "/comm").c_str());
            }
        }
        out.push_back(std::move(lp));
    }
}

void find_processes(const char* keyword, std::vector<ProcHit>& out, size_t max) {
    if (!keyword || !*keyword) return;
    DIR* d = opendir("/proc");
    if (!d) return;
    struct dirent* e;
    while (out.size() < max && (e = readdir(d)) != nullptr) {
        if (!is_pid_dir(e->d_name)) continue;
        if (strcmp(e->d_name, "self") == 0) continue;
        int pid = atoi(e->d_name);
        if (pid == getpid()) continue;      /* 别把自己当成调试器/注入者 */
        std::string base = std::string("/proc/") + e->d_name;
        std::string cmd = proc_read(pid, "cmdline");
        std::string comm = read_line_file((base + "/comm").c_str());
        for (auto& c : cmd) if (c == '\0') c = ' ';
        if (cmd.find(keyword) != std::string::npos ||
            comm.find(keyword) != std::string::npos) {
            ProcHit h;
            h.pid = pid;
            h.cmdline = cmd;
            h.comm = comm;
            out.push_back(std::move(h));
        }
    }
    closedir(d);
}

/* ---------------- 系统属性枚举 ---------------- */

namespace {
struct PropSink {
    std::vector<std::pair<std::string, std::string>>* out;
    size_t max;
};

void prop_collect(const prop_info* pi, void* cookie) {
    PropSink* sink = static_cast<PropSink*>(cookie);
    if (!sink || sink->out->size() >= sink->max) return;
    char name[PROP_NAME_MAX] = {0};
    char value[PROP_VALUE_MAX] = {0};
#if defined(__ANDROID_API__) && __ANDROID_API__ >= 26
    struct Ctx {
        PropSink* sink;
        char* name;
        char* value;
    } ctx{sink, name, value};
    __system_property_read_callback(
        pi,
        [](void* c, const char* n, const char* v, uint32_t) {
            Ctx* x = static_cast<Ctx*>(c);
            if (!x->name[0]) snprintf(x->name, PROP_NAME_MAX, "%s", n ? n : "");
            if (!x->value[0] && v) snprintf(x->value, PROP_VALUE_MAX, "%s", v);
            (void)x->sink;
        },
        &ctx);
    if (!name[0]) return;
    sink->out->emplace_back(name, value);
#else
    /* API < 26:__system_property_read 稳定可用(头里只是注释为 deprecated) */
    if (__system_property_read(pi, name, value) < 0) return;
    sink->out->emplace_back(name, value);
#endif
}
}  // namespace

void enumerate_props(std::vector<std::pair<std::string, std::string>>& out, size_t max) {
    PropSink sink{&out, max};
    __system_property_foreach(prop_collect, &sink);
}

/* ---------------- USB 物理连接(sysfs) ---------------- */

/* 注意:"USB 调试开着" 与 "数据线插着" 是两回事。这里只看内核侧
 * 是否有 USB 控制器处于 online/CONFIGURED(插了线/充电),不碰 adb
 * 开关(那要 Java 的 Settings.Global.ADB_ENABLED / UsbManager)。 */
int usb_physically_connected() {
    int known = 0;
    static const char* on[] = {
        "/sys/class/power_supply/usb/online",
        "/sys/class/power_supply/usb/present",
        "/sys/class/power_supply/usb/connected",
        "/sys/class/power_supply/usb/real_type",
    };
    for (const char* p : on) {
        std::string v = read_line_file(p);
        if (v.empty()) continue;
        known = 1;
        if (v == "1") return 1;
    }
    std::string st = read_line_file("/sys/class/android_usb/android0/state");
    if (!st.empty()) {
        known = 1;
        if (st == "CONFIGURED" || st == "CONNECTED") return 1;
    }
    /* 有 USB 控制器设备节点也算插着(部分机型 power_supply 名字不同) */
    if (path_exists("/sys/bus/usb/devices/usb1") ||
        path_exists("/sys/class/udc")) {
        std::string role = read_line_file("/sys/class/udc/fe800000.dwc3/state");
        if (role == "configured" || role == "connected") return 1;
        known = 1;
    }
    return known ? 0 : -1;
}

}  // namespace util
}  // namespace sec
