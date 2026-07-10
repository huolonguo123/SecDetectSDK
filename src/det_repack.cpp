/*
 * det_repack.cpp — 检测项 7:重打包破解(v1/v2/v3 签名指纹比对)
 *
 * 思路:APK 重打包 = 解包 → 改代码/资源 → 重新签名。重签名必然
 * 用攻击者自己的密钥,所以"当前 APK 的签名证书指纹 != 官方发布版
 * 指纹"就是重打包的铁证。
 *
 * ==================== APK 路径从哪来(两种形态) ====================
 *   a) 命令行/回调形态:input = "<apk_path>[,<基线>]"
 *   b) **App 集成形态(推荐):不回传 input**,改由 Java 回填
 *        SEC_FACT_APK_PATH      = context.getApplicationInfo().sourceDir
 *                                 (+ splitSourceDirs,多个用 '|' 分隔)
 *        SEC_FACT_APK_BASELINE  = 官方指纹基线(可多基线 d1|d2)
 *      为什么要 Java 给:native 拿不到可靠路径 —— /proc/self/exe 指向
 *      app_process64 而不是 APK;/data/app 在 Android 10+ 是 0711,
 *      列不了目录。所以"免传路径"这件事必须靠环境事实回填。
 *
 * 支持的签名方案(与 Android 平台一致,三套都要看):
 *   v1 (JAR signing)   META-INF/CERT.{RSA,DSA,EC} —— PKCS#7 里取证书
 *   v2 (APK Signature Scheme v2)  APK Signing Block id=0x7109871a
 *   v3 (APK Signature Scheme v3)  APK Signing Block id=0xf05368c0
 * 很多人只签 v2/v3(v1 已废弃),老包可能只有 v1 → 三套都解析。
 *
 * ==================== 基线(baseline)怎么定 ====================
 *   ★ 不要用"第一次运行时的指纹"当基线 —— 第一次运行的包可能已经
 *     是重打包版,那样就把攻击者指纹记成官方基线,以后永远不报。
 *   正确做法(三选一,都支持):
 *     1) CI 里对发布包跑一次校准模式,把指纹写进构建常量;
 *     2) 服务端下发基线(可随时更新,能对付密钥轮换);
 *     3) 用多基线 "d1|d2" 覆盖历史签名(Play App Signing 轮换场景)。
 *   指纹是**证书级**的(v1/v2/v3 各自解出证书再算 digest),所以只要
 *   签名密钥不变,发新版包指纹不变 → 基线固化一次可长期使用。
 *
 * 输入(input,可选)格式:
 *   "<apk_path>"                      校准模式:输出三套签名的指纹
 *   "<apk_path>,<digest>"             比对模式:digest 命中任一即算通过
 *   "<apk_path>,<d1>|<d2>|..."        多个候选基线
 *
 * digest 语义(和 Java/keytool 对齐):
 *   32 位小写 hex → 证书 DER 的 MD5(等价 keytool -printcert 的 MD5)
 *   64 位小写 hex → 证书 DER 的 SHA-256
 *   大小写不敏感。
 *
 * 局限(写进报告):
 *   - 只能证明"签名变了",不能证明"代码改了";同密钥重签不报(这是语义边界)
 *   - 需要调用方持有可信基线(CI 固化 / 服务端下发)
 *   - APK 装在 /data/app 且是只读挂载,安装后不会再变 → **启动时查一次即可**,
 *     不需要高频轮询;但本地检测可被 hook 成恒返 0,结果应上报服务端聚合裁决
 *   - split APK 每个都是独立签名的文件,必须**逐个**校验(本项已支持 '|' 多路径)
 *   - 双开/注入类不改变 APK 文件本身,属于第 6/10/11 项的范围
 */
#include "internal.h"

namespace sec {

namespace {

std::string lower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

void trim(std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    size_t e = s.find_last_not_of(" \t\r\n");
    s = (b == std::string::npos) ? std::string() : s.substr(b, e - b + 1);
}

bool is_hex(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (!isxdigit((unsigned char)c)) return false;
    return true;
}

/* 按 sep 拆字符串(用于多基线 '|' 与多 split 路径 '|') */
void split_by(const std::string& in, char sep, std::vector<std::string>& out) {
    std::string cur;
    for (char c : in) {
        if (c == sep) {
            std::string t = cur;
            trim(t);
            if (!t.empty()) out.push_back(t);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    std::string t = cur;
    trim(t);
    if (!t.empty()) out.push_back(t);
}

/* 与基线集合比对:命中任一基线(证书 MD5 或 SHA-256)即算官方包 */
bool matches_baseline(const util::ApkSignInfo& si, const std::vector<std::string>& want,
                      std::string* hit) {
    for (const auto& w : want) {
        if (!is_hex(w)) continue;
        auto eq = [&](bool has, const std::string& md5, const std::string& sha) {
            return has && (md5 == w || sha == w);
        };
        if (eq(si.has_v1, si.v1_cert_md5, si.v1_cert_sha256) ||
            eq(si.has_v2, si.v2_cert_md5, si.v2_cert_sha256) ||
            eq(si.has_v3, si.v3_cert_md5, si.v3_cert_sha256)) {
            if (hit) *hit = w;
            return true;
        }
    }
    return false;
}

std::string primary_md5(const util::ApkSignInfo& si) {
    if (si.has_v2) return si.v2_cert_md5;
    if (si.has_v3) return si.v3_cert_md5;
    return si.v1_cert_md5;
}

/* 处理单个 APK:返回 true = 判定为风险(或路径不可用) */
bool check_one_apk(const std::string& apk, const std::vector<std::string>& want,
                   bool have_baseline, const char* label, Findings& f, bool* unreadable) {
    util::ApkSignInfo si;
    bool any = util::apk_signature_info(apk.c_str(), si);
    if (unreadable) *unreadable = false;

    if (!si.note.empty()) f.add("info: %s%s", label, si.note.c_str());
    if (!any) {
        /* 完全没有签名(或文件不可读):重打包后删掉签名块 / APK 结构异常 */
        f.add("%sschemes: v1=no v2=no v3=no%s", label,
              have_baseline ? " (no signature found, baseline expects one)" : "");
        if (unreadable) *unreadable = true;
        return have_baseline;      /* 有基线却没有签名 → 判风险 */
    }

    f.add("%sschemes: v1=%s v2=%s v3=%s", label,
          si.has_v1 ? "yes" : "no", si.has_v2 ? "yes" : "no", si.has_v3 ? "yes" : "no");
    if (si.has_v1) f.add("%sv1 cert md5=%s sha256=%s", label,
                         si.v1_cert_md5.c_str(), si.v1_cert_sha256.c_str());
    if (si.has_v2) f.add("%sv2 cert md5=%s sha256=%s", label,
                         si.v2_cert_md5.c_str(), si.v2_cert_sha256.c_str());
    if (si.has_v3) f.add("%sv3 cert md5=%s sha256=%s", label,
                         si.v3_cert_md5.c_str(), si.v3_cert_sha256.c_str());

    if (!have_baseline) {
        f.add("%sfingerprint(calibration): take one of the md5/sha256 above as baseline", label);
        return false;              /* 校准模式:不判风险 */
    }

    std::string hit;
    if (matches_baseline(si, want, &hit)) {
        f.add("%ssignature matches baseline %s (official build)", label, hit.c_str());
        return false;
    }
    f.add("%ssignature MISMATCH (current md5=%s) — apk was re-signed (repacked/cracked)",
          label, primary_md5(si).c_str());
    return true;
}

}  // namespace

class RepackDetector : public BaseDetector {
public:
    const char* name() const override { return "repack"; }
    int type() const override { return DETECT_REPACK; }

    bool run(const char* input, Findings& f) override {
        /* ---- 1) 取 APK 路径与基线:input 优先,其次环境事实(Java 回填) ---- */
        std::string apk_csv, baseline;
        if (input && *input) {
            std::string in(input);
            size_t comma = in.find(',');
            if (comma == std::string::npos) {
                apk_csv = in;
            } else {
                apk_csv = in.substr(0, comma);
                baseline = in.substr(comma + 1);
            }
            trim(apk_csv);
            trim(baseline);
            if (!apk_csv.empty()) f.add("source: input");
        }
        if (apk_csv.empty() && util::env_has(SEC_FACT_APK_PATH)) {
            apk_csv = util::env_facts().apk_path;
            trim(apk_csv);
            if (!apk_csv.empty()) f.add("source: java env facts (SEC_FACT_APK_PATH)");
        }
        if (baseline.empty() && util::env_has(SEC_FACT_APK_BASELINE)) {
            baseline = util::env_facts().apk_baseline;
            trim(baseline);
            if (!baseline.empty()) f.add("baseline: java env facts (SEC_FACT_APK_BASELINE)");
        }

        if (apk_csv.empty()) {
            f.add("repack: no apk path — pass input \"<apk>[,<baseline>]\" or let Java "
                  "fill SEC_FACT_APK_PATH (context.getApplicationInfo().sourceDir)");
            return false;
        }

        /* ---- 2) 多 split / 多 APK:'|' 分隔,逐个校验 ---- */
        std::vector<std::string> apks;
        split_by(apk_csv, '|', apks);
        if (apks.empty()) {
            f.add("repack: empty apk path");
            return false;
        }

        std::vector<std::string> want;
        split_by(baseline, '|', want);
        for (auto& w : want) w = lower(w);        /* 指纹比对大小写不敏感 */
        bool have_baseline = !want.empty();
        if (have_baseline) {
            for (const auto& w : want)
                if (!is_hex(w)) f.add("warn: baseline '%s' is not hex, ignored", w.c_str());
        }

        bool risk = false;
        for (size_t i = 0; i < apks.size(); ++i) {
            char label[32];
            if (apks.size() > 1) snprintf(label, sizeof label, "apk[%u] ", (unsigned)i);
            else                 label[0] = '\0';

            /* 文件存在性先判,给出明确原因(而不是笼统的"找不到") */
            if (!util::file_exists(apks[i].c_str())) {
                f.add("%srepack: file not accessible: %s (needs root for /data/app)", label,
                      apks[i].c_str());
                risk = risk || have_baseline;   /* 有基线却读不到 → 无法证明清白,按风险上报 */
                continue;
            }
            bool unreadable = false;
            if (check_one_apk(apks[i], want, have_baseline, label, f, &unreadable))
                risk = true;
        }

        if (have_baseline && !risk)
            f.add("repack: all %zu apk(s) match official signature", apks.size());
        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_repack_detector() {
    return new sec::RepackDetector();
}
