/*
 * apk_signature.cpp — APK 签名解析(v1 JAR / v2 / v3)与证书指纹
 *
 * 用途(检测项 7 重打包):
 *   重打包 = 解包 → 改 → 重新签名,签名必然换成攻击者的密钥。
 *   所以"当前 APK 的签名证书指纹 != 官方发布版指纹"就是铁证。
 *
 * 三套签名方案在文件里的位置完全不同,要分别解析:
 *
 *   v1(JAR):META-INF/CERT.RSA(实为 PKCS#7 SignedData 的 DER)。
 *           证书藏在 SignedData 的 certificates [0] 里 —— 用最小
 *           DER 走位取出第一张 X.509 证书的完整 TLV,再算指纹。
 *
 *   v2/v3:APK Signing Block,位于「Central Directory 之前」的一段
 *          带魔数 "APK Sig Block 42" 的 id-value 区:
 *            [entries][APK Signing Block][Central Directory][EOCD]
 *          v2 块 id = 0x7109871a,v3 块 id = 0xf05368c0。
 *          signer 里 signed data 的 certificates 字段就是证书链,
 *          每张证书是"长度前缀 + DER"。
 *
 * 指纹语义与 Java 对齐:
 *   PackageInfo.signatures[i].toByteArray() = 证书 DER;
 *   keytool -printcert -jarfile x.apk 显示的 MD5 = MD5(证书 DER)。
 *   所以这里算的就是"签名证书本身的 MD5/SHA-256",可直接和
 *   `keytool`/`apksigner verify --print-certs` 的输出对照。
 */
#include "internal.h"

#include <cstdio>
#include <cstring>

namespace sec {
namespace util {

/* ==================== MD5(RFC 1321,零依赖) ==================== */

namespace {

struct Md5 {
    uint32_t a, b, c, d;
    uint64_t total;          // 已处理字节数
    uint8_t buf[64];
    size_t buflen;

    Md5() : a(0x67452301), b(0xefcdab89), c(0x98badcfe), d(0x10325476), total(0), buflen(0) {}

    static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

    void block(const uint8_t* p) {
        static const uint32_t K[64] = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
            0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
            0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
            0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
            0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
            0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
        static const uint32_t S[64] = {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

        uint32_t m[16];
        for (int i = 0; i < 16; ++i)
            m[i] = (uint32_t)p[i * 4] | (uint32_t)p[i * 4 + 1] << 8 |
                   (uint32_t)p[i * 4 + 2] << 16 | (uint32_t)p[i * 4 + 3] << 24;

        uint32_t A = a, B = b, C = c, D = d;
        for (int i = 0; i < 64; ++i) {
            uint32_t f, g;
            if (i < 16)      { f = (B & C) | (~B & D);        g = (uint32_t)i; }
            else if (i < 32) { f = (D & B) | (~D & C);        g = (uint32_t)(5 * i + 1) & 15; }
            else if (i < 48) { f = B ^ C ^ D;                 g = (uint32_t)(3 * i + 5) & 15; }
            else             { f = C ^ (B | ~D);              g = (uint32_t)(7 * i) & 15; }
            uint32_t tmp = D;
            D = C;
            C = B;
            B = B + rol(A + f + K[i] + m[g], (int)S[i]);
            A = tmp;
        }
        a += A; b += B; c += C; d += D;
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

    void final(uint8_t out[16]) {
        uint64_t bits = total * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buflen != 56) update(&zero, 1);
        uint8_t lenb[8];
        for (int i = 0; i < 8; ++i) lenb[i] = (uint8_t)(bits >> (i * 8));  // 小端
        update(lenb, 8);
        uint32_t h[4] = {a, b, c, d};
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j) out[i * 4 + j] = (uint8_t)(h[i] >> (j * 8));
    }
};

std::string hex32(const uint8_t* d, size_t n) {
    static const char* hx = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(hx[d[i] >> 4]);
        out.push_back(hx[d[i] & 0xf]);
    }
    return out;
}

}  // namespace

std::string md5_hex(const uint8_t* data, size_t len) {
    Md5 ctx;
    ctx.update(data, len);
    uint8_t d[16];
    ctx.final(d);
    return hex32(d, sizeof d);
}

std::string md5_file_hex(const char* path) {
    std::vector<uint8_t> data;
    if (!read_small_file(path, data)) return std::string();
    return md5_hex(data.data(), data.size());
}

/* ==================== 小端读取 ==================== */

namespace {

uint16_t rd16(const uint8_t* p) { return (uint16_t)(p[0] | p[1] << 8); }
uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
uint64_t rd64(const uint8_t* p) {
    return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32;
}

/* ==================== DER 最小走位(PKCS#7 取证书) ==================== */

struct Tlv {
    const uint8_t* p = nullptr;
    size_t len = 0;    // 内容长度
    size_t hdr = 0;    // 头长度(tag + 长度域)
    size_t total() const { return hdr + len; }
};

bool tlv_at(const uint8_t* p, size_t avail, Tlv& t) {
    if (avail < 2) return false;
    size_t hdr = 2, len = 0;
    if (p[1] < 0x80) {
        len = p[1];
    } else {
        int n = p[1] & 0x7f;
        if (n == 0 || n > 4 || avail < 2 + (size_t)n) return false;
        for (int i = 0; i < n; ++i) len = (len << 8) | p[2 + i];
        hdr = 2 + (size_t)n;
    }
    if (avail < hdr + len) return false;
    t.p = p;
    t.len = len;
    t.hdr = hdr;
    return true;
}

/* ContentInfo{ SEQUENCE{ OID signedData, [0]{ SignedData{ ver, algs, contentInfo,
 *                                          certificates [0] { Certificate, ... } } } } } */
bool pkcs7_first_cert(const uint8_t* d, size_t n, const uint8_t*& cert, size_t& clen) {
    Tlv ci;
    if (!tlv_at(d, n, ci) || ci.p[0] != 0x30) return false;
    const uint8_t* p = ci.p + ci.hdr;
    size_t rem = ci.len;

    Tlv oid;
    if (!tlv_at(p, rem, oid) || oid.p[0] != 0x06) return false;
    p += oid.total(); rem -= oid.total();

    Tlv ex;                                   // [0] EXPLICIT
    if (!tlv_at(p, rem, ex) || ex.p[0] != 0xA0) return false;
    p = ex.p + ex.hdr; rem = ex.len;

    Tlv sd;                                   // SignedData SEQUENCE
    if (!tlv_at(p, rem, sd) || sd.p[0] != 0x30) return false;
    p = sd.p + sd.hdr; rem = sd.len;

    Tlv v;                                    // version INTEGER
    if (!tlv_at(p, rem, v) || v.p[0] != 0x02) return false;
    p += v.total(); rem -= v.total();

    Tlv ds;                                   // digestAlgorithms SET
    if (!tlv_at(p, rem, ds) || ds.p[0] != 0x31) return false;
    p += ds.total(); rem -= ds.total();

    Tlv content;                              // contentInfo SEQUENCE
    if (!tlv_at(p, rem, content) || content.p[0] != 0x30) return false;
    p += content.total(); rem -= content.total();

    Tlv certs;                                // certificates [0] IMPLICIT SET
    if (!tlv_at(p, rem, certs) || certs.p[0] != 0xA0) return false;

    Tlv c0;
    if (!tlv_at(certs.p + certs.hdr, certs.len, c0) || c0.p[0] != 0x30) return false;
    cert = c0.p;
    clen = c0.total();
    return true;
}

/* ==================== APK Signing Block(v2/v3) ==================== */

/* 长度前缀(4 字节小端)读一段 */
bool lp_next(const uint8_t*& p, size_t& rem, const uint8_t*& out, uint32_t& outlen) {
    if (rem < 4) return false;
    uint32_t n = rd32(p);
    p += 4;
    rem -= 4;
    if (n > rem) return false;
    out = p;
    outlen = n;
    p += n;
    rem -= n;
    return true;
}

/* signer 结构(v2/v3 一致):第一个长度前缀字段就是 signed data,
 * signed data 的第二个长度前缀字段是 certificates(证书链),
 * 每张证书 = 长度前缀 + DER。取第一张。 */
bool signer_first_cert(const uint8_t* value, size_t n, const uint8_t*& cert, size_t& clen) {
    const uint8_t* p = value;
    size_t rem = n;
    const uint8_t* signers;
    uint32_t signers_len;
    if (!lp_next(p, rem, signers, signers_len)) return false;

    const uint8_t* sp = signers;
    size_t srem = signers_len;
    const uint8_t* signer;
    uint32_t signer_len;
    if (!lp_next(sp, srem, signer, signer_len)) return false;

    const uint8_t* q = signer;
    size_t qrem = signer_len;
    const uint8_t* signed_data;
    uint32_t sd_len;
    if (!lp_next(q, qrem, signed_data, sd_len)) return false;

    const uint8_t* dp = signed_data;
    size_t drem = sd_len;
    const uint8_t* tmp;
    uint32_t tmp_len;
    if (!lp_next(dp, drem, tmp, tmp_len)) return false;              // digests
    const uint8_t* certs;
    uint32_t certs_len;
    if (!lp_next(dp, drem, certs, certs_len)) return false;          // certificates

    const uint8_t* cp = certs;
    size_t crem = certs_len;
    const uint8_t* c0;
    uint32_t c0_len;
    if (!lp_next(cp, crem, c0, c0_len)) return false;
    cert = c0;
    clen = c0_len;
    return true;
}

/* 定位 EOCD 拿 Central Directory 偏移 */
bool eocd_cd_offset(FILE* fp, long fsize, uint32_t& cd_offset, uint16_t& total_entries) {
    long tail = fsize < (22 + 65535) ? fsize : (22 + 65535);
    std::vector<uint8_t> buf((size_t)tail);
    if (fseek(fp, fsize - tail, SEEK_SET) != 0) return false;
    if (fread(buf.data(), 1, buf.size(), fp) != buf.size()) return false;
    for (long i = (long)buf.size() - 22; i >= 0; --i) {
        if (rd32(&buf[(size_t)i]) == 0x06054b50) {
            uint16_t clen = rd16(&buf[(size_t)i + 20]);
            if (i + 22 + clen == (long)buf.size()) {
                total_entries = rd16(&buf[(size_t)i + 10]);
                cd_offset = rd32(&buf[(size_t)i + 16]);
                return true;
            }
        }
    }
    return false;
}

/* 从 APK Signing Block 里按 id 取 value */
bool block_find_value(const std::vector<uint8_t>& block, uint32_t want_id,
                      const uint8_t*& value, size_t& value_len) {
    if (block.size() < 32) return false;
    /* 布局:u64 size | pairs... | u64 size | magic(16) */
    size_t end = block.size() - 24;                 // pairs 结束位置
    size_t off = 8;                                 // 跳过首个 size
    while (off + 8 <= end) {
        uint64_t len = rd64(&block[off]);
        if (len < 4 || off + 8 + len > end) break;
        uint32_t id = rd32(&block[off + 8]);
        if (id == want_id) {
            value = &block[off + 12];
            value_len = (size_t)len - 4;
            return true;
        }
        off += 8 + (size_t)len;
    }
    return false;
}

}  // namespace

/* ==================== 对外:三套签名信息 ==================== */

bool apk_signature_info(const char* apk_path, ApkSignInfo& out) {
    out = ApkSignInfo();

    /* ---- v1:已有的 ZIP 导航 + PKCS#7 取证书 ---- */
    std::vector<uint8_t> sigblob;
    if (apk_first_signature(apk_path, sigblob)) {
        const uint8_t* cert = nullptr;
        size_t clen = 0;
        if (pkcs7_first_cert(sigblob.data(), sigblob.size(), cert, clen)) {
            out.has_v1 = true;
            out.v1_cert_md5 = md5_hex(cert, clen);
            out.v1_cert_sha256 = sha256_hex(cert, clen);
        } else {
            out.note = "v1 signature block present but PKCS#7 cert parse failed";
        }
    }

    /* ---- v2/v3:APK Signing Block ---- */
    FILE* fp = fopen(apk_path, "rb");
    if (!fp) {
        if (out.note.empty()) out.note = "open apk failed";
        return out.has_v1 || out.has_v2 || out.has_v3;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    if (fsize < 32) { fclose(fp); return out.has_v1; }

    uint32_t cd_offset = 0;
    uint16_t total_entries = 0;
    if (!eocd_cd_offset(fp, fsize, cd_offset, total_entries) ||
        cd_offset < 32 || cd_offset >= (uint32_t)fsize) {
        fclose(fp);
        return out.has_v1;
    }

    /* 魔数在 CD 前 16 字节,块总长在魔数前 8 字节 */
    uint8_t tailhdr[24];
    if (fseek(fp, (long)cd_offset - 24, SEEK_SET) != 0 ||
        fread(tailhdr, 1, sizeof tailhdr, fp) != sizeof tailhdr) {
        fclose(fp);
        return out.has_v1;
    }
    static const char kMagic[16] = {'A', 'P', 'K', ' ', 'S', 'i', 'g', ' ',
                                    'B', 'l', 'o', 'c', 'k', ' ', '4', '2'};
    if (memcmp(tailhdr + 8, kMagic, 16) != 0) {
        /* 没有签名块(可能 v1-only 或 v2/v3 均未签名) */
        fclose(fp);
        return out.has_v1;
    }
    uint64_t block_size = rd64(tailhdr);            // 含尾部 size+magic
    if (block_size < 32 || block_size > 64ULL * 1024 * 1024) {
        out.note = "apk signing block size out of range";
        fclose(fp);
        return out.has_v1;
    }
    uint64_t block_start = (uint64_t)cd_offset - (block_size + 8);
    if (block_start > (uint64_t)cd_offset) { fclose(fp); return out.has_v1; }

    std::vector<uint8_t> block((size_t)(block_size + 8));
    if (fseek(fp, (long)block_start, SEEK_SET) != 0 ||
        fread(block.data(), 1, block.size(), fp) != block.size()) {
        out.note = "read apk signing block failed";
        fclose(fp);
        return out.has_v1;
    }
    fclose(fp);

    struct { uint32_t id; bool* flag; std::string* md5; std::string* sha; } schemes[] = {
        {0x7109871a, &out.has_v2, &out.v2_cert_md5, &out.v2_cert_sha256},   // v2
        {0xf05368c0, &out.has_v3, &out.v3_cert_md5, &out.v3_cert_sha256},   // v3
    };
    for (auto& s : schemes) {
        const uint8_t* value = nullptr;
        size_t vlen = 0;
        if (!block_find_value(block, s.id, value, vlen)) continue;
        const uint8_t* cert = nullptr;
        size_t clen = 0;
        if (signer_first_cert(value, vlen, cert, clen)) {
            *s.flag = true;
            *s.md5 = md5_hex(cert, clen);
            *s.sha = sha256_hex(cert, clen);
        } else if (out.note.empty()) {
            out.note = "signing block present but signer cert parse failed";
        }
    }
    return out.has_v1 || out.has_v2 || out.has_v3;
}

}  // namespace util
}  // namespace sec
