/*
 * det_repack.cpp — 检测项 7:重打包破解(APK 签名指纹比对)
 *
 * 思路:APK 重打包 = 解包 → 改代码/资源 → 重新签名。重签名必然
 * 用攻击者自己的密钥,所以"当前 APK 的签名指纹 != 官方发布版
 * 指纹"就是重打包的铁证。
 *
 * 实现:输入 APK 路径(可选带官方基线指纹),SDK 自己解析 zip:
 *   1. 尾部扫 EOCD 拿到 Central Directory;
 *   2. 遍历 CD 找 META-INF 目录下的 v1 签名文件(.RSA/.DSA/.EC);
 *   3. 定位 Local File Header 读出签名文件原始字节(stored 直读,
 *      deflate 用 zlib 解),算 SHA-256;
 *   4. 与基线比对。
 *
 * 局限(必须写进报告):
 *   - 只覆盖 v1(JAR)签名;只做 v2/v3 签名的 APK 没有 META-INF
 *     签名文件,需解析 APK Signature Block(产品里建议 Java 层
 *     用 PackageManager 的 GET_SIGNING_CERTIFICATES 直接拿证书
 *     digest,更省事也更权威);
 *   - 检测"指纹变没变"需要调用方持有官方基线(发布包 CI 里固化);
 *   - 双开/注入类不改变 APK 文件本身,不属于本项检测范围。
 */
#include "internal.h"

namespace sec {

namespace {

std::string lower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

}  // namespace

class RepackDetector : public BaseDetector {
public:
    const char* name() const override { return "repack"; }
    int type() const override { return DETECT_REPACK; }
    bool needs_input() const override { return true; }

    bool run(const char* input, Findings& f) override {
        /* input 在 api 层已校验非空且 APK 存在;这里拆基线 */
        std::string in(input);
        std::string apk = in;
        std::string baseline;
        size_t comma = in.find(',');
        if (comma != std::string::npos) {
            apk = in.substr(0, comma);
            baseline = lower(in.substr(comma + 1));
            /* 去掉可能的前后空白 */
            auto trim = [](std::string& s) {
                size_t b = s.find_first_not_of(" \t");
                size_t e = s.find_last_not_of(" \t");
                s = (b == std::string::npos) ? "" : s.substr(b, e - b + 1);
            };
            trim(apk);
            trim(baseline);
        }

        std::vector<uint8_t> sig;
        if (!util::apk_first_signature(apk.c_str(), sig)) {
            /* 没有 v1 签名块 */
            if (!baseline.empty()) {
                /* 官方版有 v1、当前没有 = 被重新打包处理过 */
                f.add("repack: v1 signature block MISSING (baseline expects one)");
                return true;
            }
            f.add("info: no META-INF v1 signature (v2/v3-only apk); "
                  "use platform signing-cert digest to fingerprint");
            return false;
        }

        std::string cur = util::sha256_hex(sig.data(), sig.size());

        if (baseline.empty()) {
            /* 校准模式:不判风险,把当前指纹吐给调用方当基线 */
            f.add("fingerprint: %s", cur.c_str());
            return false;
        }

        if (lower(cur) != baseline) {
            f.add("repack: signature mismatch cur=%s base=%s",
                  cur.c_str(), baseline.c_str());
            return true;
        }
        return false;   /* 指纹一致:未发现重打包 */
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_repack_detector() {
    return new sec::RepackDetector();
}
